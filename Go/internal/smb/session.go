// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"context"
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/medianexapp/go-smb2"
	"github.com/specterops/sharehound/internal/auth"
	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/credentials"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/utils"
)

// ShareInfo holds information about an SMB share.
type ShareInfo struct {
	Name               string
	Type               []string
	RawType            uint32
	Comment            string
	SecurityDescriptor []byte
}

// FileInfo holds information about a file or directory.
type FileInfo struct {
	Name         string
	IsDir        bool
	Size         int64
	CreatedTime  time.Time
	ModifiedTime time.Time
}

// SMBSession represents an SMB session for interacting with an SMB server.
type SMBSession struct {
	config         *config.Config
	log            logger.LoggerInterface
	host           string
	remoteName     string
	port           int
	timeout        time.Duration
	advertisedName string
	credentials    *credentials.Credentials

	conn      net.Conn
	session   *smb2.Session
	share     *smb2.Share
	connected bool

	availableShares map[string]ShareInfo
	currentShare    string
	currentCwd      string
	nativeWindows   bool
	nativeConnected bool
	nativeResource  string

	// SRVSVC client for share-level security descriptors
	srvsvcClient *SRVSVCClient

	// For forceful timeout handling
	mu sync.Mutex
}

// NewSMBSession creates a new SMBSession.
func NewSMBSession(
	host string,
	port int,
	timeout time.Duration,
	creds *credentials.Credentials,
	remoteName string,
	advertisedName string,
	cfg *config.Config,
	log logger.LoggerInterface,
) *SMBSession {
	if remoteName == "" {
		remoteName = host
	}

	return &SMBSession{
		config:          cfg,
		log:             log,
		host:            host,
		remoteName:      remoteName,
		port:            port,
		timeout:         timeout,
		advertisedName:  advertisedName,
		credentials:     creds,
		availableShares: make(map[string]ShareInfo),
	}
}

// Connect establishes a connection to the SMB server.
func (s *SMBSession) Connect() error {
	s.log.Debug(fmt.Sprintf("[>] Connecting to remote SMB server '%s'...", s.host))

	// Check if port is open first
	ok, err := utils.IsPortOpen(s.host, s.port, s.timeout)
	if !ok {
		s.log.Debug(fmt.Sprintf("Could not connect to '%s:%d', %v", s.host, s.port, err))
		return ErrConnectionFailed
	}

	// Connect to SMB server
	address := fmt.Sprintf("%s:%d", s.host, s.port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		s.log.Debug(fmt.Sprintf("[NETWORK] Could not connect to '%s': %v", address, err))
		return ErrConnectionFailed
	}
	s.conn = conn

	initiator, authMode, err := s.newInitiator()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to initialize SMB authentication: %w", err)
	}

	// Create SMB dialer
	dialer := &smb2.Dialer{
		Initiator: initiator,
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Dial SMB session using DialConn with the existing connection
	session, err := dialer.DialConn(ctx, conn, address)
	if err != nil {
		classification := ClassifyError(err)
		s.log.Debug(fmt.Sprintf("[%s] Authentication failed: %s", classification.Category, classification.Message))
		conn.Close()
		s.conn = nil
		if s.credentials.WindowsAuth && s.activateNativeWindowsFallback("SMB authentication failed") {
			s.connected = true
			s.log.Debug(fmt.Sprintf("[+] Using Windows-native SMB access to '%s' with current logon session", s.remoteName))
			return nil
		}
		return ErrAuthFailed
	}

	s.session = session
	s.connected = true
	if s.credentials.WindowsAuth {
		if err := s.enableNativeWindowsFallback(); err != nil {
			s.log.Debug(fmt.Sprintf("Windows-native SMB fallback is unavailable for '%s': %v", s.remoteName, err))
		}
	}

	s.log.Debug(fmt.Sprintf("[+] Successfully authenticated to '%s' with %s as '%s\\%s'!",
		s.host, authMode, s.credentials.Domain, s.credentials.Username))

	return nil
}

func (s *SMBSession) newInitiator() (smb2.Initiator, string, error) {
	if s.credentials.WindowsAuth {
		initiator, err := newSSPIKrb5Initiator(auth.ServicePrincipal("cifs", s.remoteName))
		if err != nil {
			return nil, "", err
		}
		return initiator, "Kerberos SSPI", nil
	}

	if s.credentials.UseKerberos {
		client, err := auth.NewKerberosClient(auth.KerberosOptions{
			Domain:     s.credentials.Domain,
			Username:   s.credentials.Username,
			Password:   s.credentials.Password,
			KeytabPath: s.credentials.AESKey,
			KDCHost:    s.credentials.KDCHost,
		})
		if err != nil {
			return nil, "", err
		}
		return &smb2.Krb5Initiator{
			Client:    client,
			TargetSPN: auth.ServicePrincipal("cifs", s.remoteName),
		}, "Kerberos", nil
	}

	return &smb2.NTLMInitiator{
		User:     s.credentials.Username,
		Password: s.credentials.Password,
		Domain:   s.credentials.Domain,
		Hash:     s.credentials.NTRaw,
	}, "NTLM", nil
}

func (s *SMBSession) activateNativeWindowsFallback(reason string) bool {
	if !s.canUseNativeWindowsFallback() {
		return false
	}
	if err := s.enableNativeWindowsFallback(); err != nil {
		s.log.Debug(fmt.Sprintf("Windows-native SMB fallback activation failed after %s: %v", reason, err))
		return false
	}
	s.log.Debug(fmt.Sprintf("Using Windows-native SMB fallback for '%s' after %s", s.remoteName, reason))
	return true
}

// Close closes the SMB session.
func (s *SMBSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.srvsvcClient != nil {
		s.srvsvcClient.Close()
		s.srvsvcClient = nil
	}
	if s.share != nil {
		s.share.Umount()
		s.share = nil
	}
	if s.session != nil {
		s.session.Logoff()
		s.session = nil
	}
	s.closeNativeWindowsFallback()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.connected = false
	s.log.Debug("[+] SMB connection closed successfully.")
	return nil
}

// ForceClose forcefully closes the connection by setting an immediate deadline.
// This will cause any blocking operations to fail with a timeout error.
// Uses TryLock to avoid deadlocking with goroutines that hold s.mu while
// performing blocking network I/O.
func (s *SMBSession) ForceClose() error {
	if s.mu.TryLock() {
		// Got the lock - full cleanup path
		if s.conn != nil {
			s.log.Debug(fmt.Sprintf("[FORCECLOSE] Closing connection for %s", s.host))
			s.conn.SetDeadline(time.Now())
			s.conn.Close()
			s.conn = nil
		} else {
			s.log.Debug(fmt.Sprintf("[FORCECLOSE] No connection to close for %s", s.host))
		}
		if s.srvsvcClient != nil {
			s.srvsvcClient.Close()
			s.srvsvcClient = nil
		}
		s.closeNativeWindowsFallback()
		s.share = nil
		s.session = nil
		s.connected = false
		s.mu.Unlock()
		return nil
	}

	// Could not acquire lock - another goroutine holds it and is likely
	// blocked on network I/O. Directly close the TCP connection to interrupt
	// the blocking operation. net.Conn.Close() is safe for concurrent use
	// and will cause any blocked Read/Write to return with an error.
	// We read s.conn without the lock; this is a controlled race that is
	// safe because: (a) conn is set once in Connect() and only nil'd under
	// mu, (b) Close() on net.Conn is goroutine-safe, (c) the worst case is
	// a nil-check race which we guard with the nil check.
	conn := s.conn
	if conn != nil {
		s.log.Debug(fmt.Sprintf("[FORCECLOSE] Lock held - force-closing TCP for %s", s.host))
		conn.SetDeadline(time.Now())
		conn.Close()
	}
	// The goroutine holding mu will get an I/O error, release mu, and
	// subsequent ForceClose calls (from the 500ms ticker) will acquire
	// the lock and do the full cleanup.
	return nil
}

// IsConnected returns whether the session is connected.
func (s *SMBSession) IsConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nativeWindows {
		return s.connected
	}
	return s.connected && s.session != nil
}

// Ping tests the connection.
func (s *SMBSession) Ping() bool {
	if s.nativeWindows {
		_, err := s.listSharesNative()
		return err == nil
	}

	s.mu.Lock()
	if !s.connected || s.session == nil {
		s.mu.Unlock()
		return false
	}
	session := s.session
	s.mu.Unlock()

	// Try to list shares as a ping test
	_, err := session.ListSharenames()
	if err == nil {
		return true
	}
	if s.activateNativeWindowsFallback("SMB ping failed") {
		_, err = s.listSharesNative()
		return err == nil
	}
	return false
}

// ListShares lists all available shares on the server.
func (s *SMBSession) ListShares() (map[string]ShareInfo, error) {
	if s.nativeWindows {
		shares, err := s.listSharesNative()
		if err != nil {
			return nil, err
		}
		s.availableShares = shares
		return s.availableShares, nil
	}

	s.mu.Lock()
	if !s.connected || s.session == nil {
		s.mu.Unlock()
		return nil, ErrNotConnected
	}
	session := s.session
	s.mu.Unlock()

	s.availableShares = make(map[string]ShareInfo)

	names, err := session.ListSharenames()
	if err != nil {
		if s.activateNativeWindowsFallback("share enumeration failed") {
			shares, nativeErr := s.listSharesNative()
			if nativeErr == nil {
				s.availableShares = shares
				return s.availableShares, nil
			}
			s.log.Debug(fmt.Sprintf("Windows-native share enumeration fallback failed: %v", nativeErr))
		}
		s.log.Debug(fmt.Sprintf("Could not list shares: %v", err))
		return nil, err
	}

	for _, name := range names {
		info := ShareInfo{
			Name: name,
			Type: utils.STYPEMask(0), // go-smb2 doesn't provide share type
		}
		s.availableShares[strings.ToLower(name)] = info
	}

	return s.availableShares, nil
}

// SetShare sets the current share.
// IMPORTANT: Does NOT hold s.mu during network operations (Mount/Umount)
// to allow ForceClose to interrupt blocked I/O.
func (s *SMBSession) SetShare(shareName string) error {
	if s.nativeWindows {
		s.currentShare = shareName
		s.currentCwd = ""
		return nil
	}

	s.mu.Lock()
	if !s.connected || s.session == nil {
		s.mu.Unlock()
		return ErrNotConnected
	}
	session := s.session
	oldShare := s.share
	s.share = nil // Mark as transitioning
	s.mu.Unlock()

	// Unmount current share WITHOUT holding mutex
	if oldShare != nil {
		oldShare.Umount()
	}

	// Mount the new share WITHOUT holding mutex
	share, err := session.Mount(shareName)
	if err != nil {
		if s.activateNativeWindowsFallback(fmt.Sprintf("mounting share '%s' failed", shareName)) {
			s.currentShare = shareName
			s.currentCwd = ""
			return nil
		}
		s.log.Debug(fmt.Sprintf("Could not access share '%s': %v", shareName, err))
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if we were force-closed while doing the Mount
	if !s.connected {
		share.Umount()
		return ErrNotConnected
	}

	s.share = share
	s.currentShare = shareName
	s.currentCwd = ""

	return nil
}

// GetCurrentShare returns the current share name.
func (s *SMBSession) GetCurrentShare() string {
	return s.currentShare
}

// SetCwd sets the current working directory.
func (s *SMBSession) SetCwd(dir string) {
	s.currentCwd = dir
}

// GetCwd returns the current working directory.
func (s *SMBSession) GetCwd() string {
	return s.currentCwd
}

// ListContents lists the contents of a directory.
func (s *SMBSession) ListContents(dirPath string) (map[string]FileInfo, error) {
	if s.nativeWindows {
		return s.listContentsNative(dirPath)
	}

	s.mu.Lock()
	if s.share == nil || !s.connected {
		s.mu.Unlock()
		return nil, ErrShareNotSet
	}
	share := s.share
	s.mu.Unlock()

	// Build full path
	fullPath := dirPath
	if s.currentCwd != "" && !strings.HasPrefix(dirPath, "\\") && !strings.HasPrefix(dirPath, "/") {
		fullPath = path.Join(s.currentCwd, dirPath)
	}

	// Normalize path separators
	fullPath = strings.ReplaceAll(fullPath, "/", "\\")
	if fullPath == "" {
		fullPath = "."
	}

	contents := make(map[string]FileInfo)

	entries, err := share.ReadDir(fullPath)
	if err != nil {
		if s.activateNativeWindowsFallback(fmt.Sprintf("listing contents of '%s' failed", fullPath)) {
			return s.listContentsNative(dirPath)
		}
		s.log.Debug(fmt.Sprintf("Error listing contents of '%s': %v", fullPath, err))
		return nil, err
	}

	for _, info := range entries {
		fi := FileInfo{
			Name:         info.Name(),
			IsDir:        info.IsDir(),
			Size:         info.Size(),
			ModifiedTime: info.ModTime(),
		}
		// Try to get creation time from underlying FileStat
		if fileStat, ok := info.(*smb2.FileStat); ok {
			fi.CreatedTime = fileStat.CreationTime
		}
		contents[info.Name()] = fi
	}

	return contents, nil
}

// GetFileSecurityDescriptor gets the NTFS security descriptor for a file or directory.
// This uses the medianexapp/go-smb2 fork which has native SecurityInfoRaw() support.
func (s *SMBSession) GetFileSecurityDescriptor(filePath string) (*SecurityDescriptor, error) {
	if s.nativeWindows {
		sdBytes, err := s.getFileSecurityDescriptorNative(filePath)
		if err != nil || len(sdBytes) == 0 {
			return nil, err
		}
		return ParseSecurityDescriptor(sdBytes)
	}

	s.mu.Lock()
	if s.share == nil || !s.connected {
		s.mu.Unlock()
		return nil, ErrShareNotSet
	}
	share := s.share
	s.mu.Unlock()

	// Normalize path
	fullPath := strings.ReplaceAll(filePath, "/", "\\")
	if fullPath == "" {
		fullPath = "."
	}

	// Try to get security descriptor using go:linkname approach
	sdBytes, err := QuerySecurityDescriptorLinked(share, fullPath)
	if err != nil {
		if s.activateNativeWindowsFallback(fmt.Sprintf("querying security descriptor for '%s' failed", fullPath)) {
			sdBytes, nativeErr := s.getFileSecurityDescriptorNative(filePath)
			if nativeErr == nil && len(sdBytes) != 0 {
				return ParseSecurityDescriptor(sdBytes)
			}
			s.log.Debug(fmt.Sprintf("Windows-native security descriptor fallback failed for '%s': %v", fullPath, nativeErr))
		}
		// Log debug but don't fail - this is expected in some cases
		s.log.Debug(fmt.Sprintf("Could not get security descriptor for '%s': %v", fullPath, err))
		return nil, nil
	}

	if len(sdBytes) == 0 {
		return nil, nil
	}

	// Parse the security descriptor
	return ParseSecurityDescriptor(sdBytes)
}

// GetShareSecurityDescriptor gets the share-level security descriptor via SRVSVC RPC.
// IMPORTANT: Does NOT hold s.mu during SRVSVC client creation (network I/O)
// to allow ForceClose to interrupt blocked operations.
func (s *SMBSession) GetShareSecurityDescriptor(shareName string) ([]byte, error) {
	if s.nativeWindows {
		return nil, fmt.Errorf("share-level security descriptor unavailable in Windows-native SMB fallback")
	}

	s.mu.Lock()
	if !s.connected || s.session == nil {
		s.mu.Unlock()
		return nil, ErrNotConnected
	}
	session := s.session
	srvsvcClient := s.srvsvcClient
	s.mu.Unlock()

	// Initialize SRVSVC client if needed — WITHOUT holding mutex
	if srvsvcClient == nil {
		client, err := NewSRVSVCClient(session)
		if err != nil {
			s.log.Debug(fmt.Sprintf("Failed to create SRVSVC client: %v", err))
			return nil, fmt.Errorf("SRVSVC not available: %w", err)
		}
		// Store client under lock
		s.mu.Lock()
		if !s.connected {
			s.mu.Unlock()
			client.Close()
			return nil, ErrNotConnected
		}
		if s.srvsvcClient == nil {
			s.srvsvcClient = client
			srvsvcClient = client
		} else {
			// Another goroutine already created it — use theirs, close ours
			client.Close()
			srvsvcClient = s.srvsvcClient
		}
		s.mu.Unlock()
	}

	// Query share security descriptor via SRVSVC
	sd, err := srvsvcClient.GetShareSecurityDescriptor(s.remoteName, shareName)
	if err != nil {
		s.log.Debug(fmt.Sprintf("Failed to get share security descriptor via SRVSVC: %v", err))
		return nil, err
	}

	return sd, nil
}

// GetShareRootSecurityDescriptor gets the NTFS security descriptor of the share root.
// This is used as a fallback when SRVSVC is not available.
// It uses QuerySecurityDescriptorLinked (medianexapp/go-smb2 fork) to query the
// root directory's security descriptor, matching the Python implementation's fallback.
func (s *SMBSession) GetShareRootSecurityDescriptor(shareName string) ([]byte, error) {
	if s.nativeWindows {
		return s.getShareRootSecurityDescriptorNative(shareName)
	}

	s.mu.Lock()
	if !s.connected || s.session == nil {
		s.mu.Unlock()
		return nil, ErrNotConnected
	}
	session := s.session
	s.mu.Unlock()

	// Mount the target share directly (don't use SetShare to avoid disrupting
	// the current share state used by other operations)
	share, err := session.Mount(shareName)
	if err != nil {
		if s.activateNativeWindowsFallback(fmt.Sprintf("mounting share root '%s' failed", shareName)) {
			return s.getShareRootSecurityDescriptorNative(shareName)
		}
		return nil, fmt.Errorf("failed to mount share '%s': %w", shareName, err)
	}
	defer share.Umount()

	// Use QuerySecurityDescriptorLinked to get the root directory's security descriptor.
	// This is the same method used by GetFileSecurityDescriptor for files/directories,
	// applied to the root path "." of the share.
	sdBytes, err := QuerySecurityDescriptorLinked(share, ".")
	if err != nil {
		if s.activateNativeWindowsFallback(fmt.Sprintf("querying root security descriptor for share '%s' failed", shareName)) {
			return s.getShareRootSecurityDescriptorNative(shareName)
		}
		return nil, fmt.Errorf("failed to query root security descriptor for share '%s': %w", shareName, err)
	}

	if len(sdBytes) == 0 {
		s.log.Debug(fmt.Sprintf("Share root '%s' accessible but security descriptor is empty", shareName))
		return nil, nil
	}

	s.log.Debug(fmt.Sprintf("Successfully retrieved root security descriptor for share '%s' (%d bytes)", shareName, len(sdBytes)))
	return sdBytes, nil
}

// GetSession returns the underlying SMB2 session.
func (s *SMBSession) GetSession() *smb2.Session {
	return s.session
}

// GetRemoteName returns the remote server name.
func (s *SMBSession) GetRemoteName() string {
	return s.remoteName
}

// GetRemoteHost returns the remote host IP/hostname.
func (s *SMBSession) GetRemoteHost() string {
	return s.host
}
