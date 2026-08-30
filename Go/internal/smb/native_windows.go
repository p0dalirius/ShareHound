//go:build windows

package smb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/specterops/sharehound/internal/utils"
	"golang.org/x/sys/windows"
)

const (
	netapiMaxPreferredLength = 0xffffffff
	nerrSuccess              = 0
	errorMoreData            = 234
	noError                  = 0
	connectTemporary         = 0x00000004
	resourceTypeDisk         = 0x00000001

	seFileObject             = 1
	ownerSecurityInformation = 0x00000001
	groupSecurityInformation = 0x00000002
	daclSecurityInformation  = 0x00000004
)

type shareInfo1 struct {
	NetName *uint16
	Type    uint32
	Remark  *uint16
}

type netResource struct {
	Scope       uint32
	Type        uint32
	DisplayType uint32
	Usage       uint32
	LocalName   *uint16
	RemoteName  *uint16
	Comment     *uint16
	Provider    *uint16
}

var (
	modNetapi32 = windows.NewLazySystemDLL("netapi32.dll")
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modMpr      = windows.NewLazySystemDLL("mpr.dll")

	procNetShareEnum                = modNetapi32.NewProc("NetShareEnum")
	procNetApiBufferFree            = modNetapi32.NewProc("NetApiBufferFree")
	procGetNamedSecurityInfoW       = modAdvapi32.NewProc("GetNamedSecurityInfoW")
	procGetSecurityDescriptorLength = modAdvapi32.NewProc("GetSecurityDescriptorLength")
	procLocalFree                   = modKernel32.NewProc("LocalFree")
	procWNetAddConnection2W         = modMpr.NewProc("WNetAddConnection2W")
	procWNetCancelConnection2W      = modMpr.NewProc("WNetCancelConnection2W")
)

func (s *SMBSession) canUseNativeWindowsFallback() bool {
	if s.credentials.WindowsAuth {
		return true
	}
	if s.credentials.Username == "" || s.credentials.Password == "" {
		return false
	}
	if s.credentials.HasHashes() || s.credentials.AESKey != "" {
		return false
	}
	return true
}

func (s *SMBSession) enableNativeWindowsFallback() error {
	if s.nativeWindows {
		return nil
	}
	if !s.canUseNativeWindowsFallback() {
		return fmt.Errorf("no Windows-compatible credentials are available for native SMB fallback")
	}

	if s.credentials.WindowsAuth {
		s.nativeWindows = true
		return nil
	}

	resource := fmt.Sprintf(`\\%s\IPC$`, s.remoteName)
	remoteName, err := windows.UTF16PtrFromString(resource)
	if err != nil {
		return err
	}
	username, err := windows.UTF16PtrFromString(s.nativeUsername())
	if err != nil {
		return err
	}
	password, err := windows.UTF16PtrFromString(s.credentials.Password)
	if err != nil {
		return err
	}

	nr := netResource{
		Type:       resourceTypeDisk,
		RemoteName: remoteName,
	}

	ret, _, _ := procWNetAddConnection2W.Call(
		uintptr(unsafe.Pointer(&nr)),
		uintptr(unsafe.Pointer(password)),
		uintptr(unsafe.Pointer(username)),
		uintptr(connectTemporary),
	)
	if ret != noError {
		return windows.Errno(ret)
	}

	s.nativeConnected = true
	s.nativeResource = resource
	s.nativeWindows = true
	return nil
}

func (s *SMBSession) closeNativeWindowsFallback() {
	if !s.nativeConnected || s.nativeResource == "" {
		return
	}
	resource, err := windows.UTF16PtrFromString(s.nativeResource)
	if err == nil {
		procWNetCancelConnection2W.Call(uintptr(unsafe.Pointer(resource)), 0, 1)
	}
	s.nativeConnected = false
	s.nativeResource = ""
}

func (s *SMBSession) nativeUsername() string {
	username := s.credentials.Username
	if username == "" || strings.Contains(username, `\`) || strings.Contains(username, "@") || s.credentials.Domain == "" {
		return username
	}
	return s.credentials.Domain + `\` + username
}

func (s *SMBSession) listSharesNative() (map[string]ShareInfo, error) {
	serverName := s.remoteName
	if !strings.HasPrefix(serverName, `\\`) {
		serverName = `\\` + serverName
	}

	serverPtr, err := windows.UTF16PtrFromString(serverName)
	if err != nil {
		return nil, err
	}

	shares := make(map[string]ShareInfo)
	var resume uint32

	for {
		var buffer uintptr
		var entriesRead uint32
		var totalEntries uint32

		ret, _, _ := procNetShareEnum.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			uintptr(1),
			uintptr(unsafe.Pointer(&buffer)),
			uintptr(netapiMaxPreferredLength),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resume)),
		)
		if buffer != 0 {
			defer procNetApiBufferFree.Call(buffer)
		}
		if ret != nerrSuccess && ret != errorMoreData {
			return nil, windows.Errno(ret)
		}

		if entriesRead > 0 {
			items := unsafe.Slice((*shareInfo1)(unsafe.Pointer(buffer)), entriesRead)
			for _, item := range items {
				name := windows.UTF16PtrToString(item.NetName)
				if name == "" {
					continue
				}
				shares[strings.ToLower(name)] = ShareInfo{
					Name:    name,
					Type:    utils.STYPEMask(item.Type),
					RawType: item.Type,
					Comment: windows.UTF16PtrToString(item.Remark),
				}
			}
		}

		if ret != errorMoreData {
			break
		}
	}

	return shares, nil
}

func (s *SMBSession) listContentsNative(dirPath string) (map[string]FileInfo, error) {
	if s.currentShare == "" {
		return nil, ErrShareNotSet
	}

	fullPath := s.nativeUNCPath(s.currentShare, dirPath)
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	contents := make(map[string]FileInfo, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		contents[entry.Name()] = FileInfo{
			Name:         entry.Name(),
			IsDir:        entry.IsDir(),
			Size:         info.Size(),
			ModifiedTime: info.ModTime(),
		}
	}

	return contents, nil
}

func (s *SMBSession) getFileSecurityDescriptorNative(filePath string) ([]byte, error) {
	if s.currentShare == "" {
		return nil, ErrShareNotSet
	}
	return getNamedSecurityDescriptor(s.nativeUNCPath(s.currentShare, filePath))
}

func (s *SMBSession) getShareRootSecurityDescriptorNative(shareName string) ([]byte, error) {
	return getNamedSecurityDescriptor(s.nativeUNCPath(shareName, ""))
}

func (s *SMBSession) nativeUNCPath(shareName string, itemPath string) string {
	base := fmt.Sprintf(`\\%s\%s`, s.remoteName, shareName)
	itemPath = strings.ReplaceAll(itemPath, "/", `\`)
	itemPath = strings.Trim(itemPath, `\`)
	if itemPath == "" || itemPath == "." {
		return base
	}
	return filepath.Join(base, itemPath)
}

func getNamedSecurityDescriptor(path string) ([]byte, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	var sd uintptr
	ret, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(ownerSecurityInformation|groupSecurityInformation|daclSecurityInformation),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&sd)),
	)
	if ret != 0 {
		return nil, windows.Errno(ret)
	}
	if sd == 0 {
		return nil, nil
	}
	defer procLocalFree.Call(sd)

	length, _, _ := procGetSecurityDescriptorLength.Call(sd)
	if length == 0 {
		return nil, nil
	}

	data := unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(length))
	return append([]byte(nil), data...), nil
}
