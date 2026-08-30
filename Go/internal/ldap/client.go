// Package ldap provides LDAP client functionality for Active Directory queries.
package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
	"github.com/specterops/sharehound/internal/auth"
	"github.com/specterops/sharehound/internal/credentials"
)

// Default page size for LDAP paging (AD default MaxPageSize is 1000)
const defaultPageSize = 1000

// Client represents an LDAP client for Active Directory.
type Client struct {
	conn        *ldap.Conn
	baseDN      string
	domain      string
	dcIP        string
	username    string
	password    string
	authKey     string
	useLDAPS    bool
	useNTLM     bool
	ntHash      string
	useKerberos bool
	windowsAuth bool
	kdcHost     string
}

// ClientOptions holds options for creating an LDAP client.
type ClientOptions struct {
	Domain      string
	DCIP        string
	Username    string
	Password    string
	Hashes      string // LM:NT format
	AuthKey     string
	UseLDAPS    bool
	UseKerberos bool
	WindowsAuth bool
	KDCHost     string
}

// NewClient creates a new LDAP client.
func NewClient(opts *ClientOptions) (*Client, error) {
	client := &Client{
		domain:      opts.Domain,
		dcIP:        opts.DCIP,
		username:    opts.Username,
		password:    opts.Password,
		authKey:     opts.AuthKey,
		useLDAPS:    opts.UseLDAPS,
		useKerberos: opts.UseKerberos,
		windowsAuth: opts.WindowsAuth,
		kdcHost:     opts.KDCHost,
	}

	// Parse hashes if provided
	if opts.Hashes != "" {
		_, ntHash := credentials.ParseLMNTHashes(opts.Hashes)
		if ntHash != "" {
			client.ntHash = ntHash
			client.useNTLM = true
		}
	}

	// Build base DN from domain
	client.baseDN = domainToBaseDN(opts.Domain)

	return client, nil
}

// Connect establishes connection to the LDAP server.
func (c *Client) Connect() error {
	var err error
	var conn *ldap.Conn

	if c.useLDAPS {
		// LDAPS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:636", c.dcIP), tlsConfig)
	} else {
		// Plain LDAP connection
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:389", c.dcIP))
	}

	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	c.conn = conn

	if err := c.bind(); err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to bind to LDAP server: %w", err)
	}

	return nil
}

func (c *Client) bind() error {
	if c.windowsAuth {
		gssClient, err := newWindowsGSSAPIClient(c.tlsServerCertificate())
		if err != nil {
			return err
		}
		return c.conn.GSSAPIBind(gssClient, c.ldapServicePrincipal(), "")
	}

	if c.useKerberos {
		krbClient, err := auth.NewKerberosClient(auth.KerberosOptions{
			Domain:     c.domain,
			Username:   c.username,
			Password:   c.password,
			KeytabPath: c.authKey,
			KDCHost:    c.kdcHost,
		})
		if err != nil {
			return err
		}
		gssClient := &ldapgssapi.Client{Client: krbClient}
		return c.conn.GSSAPIBind(gssClient, c.ldapServicePrincipal(), "")
	}

	if c.useNTLM {
		return c.conn.NTLMBindWithHash(c.domain, c.username, c.ntHash)
	}

	bindDN := fmt.Sprintf("%s@%s", c.username, c.domain)
	return c.conn.Bind(bindDN, c.password)
}

func (c *Client) tlsServerCertificate() *x509.Certificate {
	if !c.useLDAPS || c.conn == nil {
		return nil
	}
	state, ok := c.conn.TLSConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
}

func (c *Client) ldapServicePrincipal() string {
	host := c.dcIP
	if c.kdcHost != "" && net.ParseIP(host) != nil {
		host = c.kdcHost
	} else if net.ParseIP(host) != nil {
		if names, err := net.LookupAddr(host); err == nil && len(names) > 0 {
			host = strings.TrimSuffix(names[0], ".")
		}
	}
	return auth.ServicePrincipal("ldap", host)
}

// Close closes the LDAP connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// GetComputers retrieves all computer objects from AD using paging.
func (c *Client) GetComputers() ([]string, error) {
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=computer)(objectClass=computer))",
		[]string{"dNSHostName", "name"},
		nil,
	)

	// Use paging to handle large result sets
	sr, err := c.conn.SearchWithPaging(searchRequest, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var computers []string
	for _, entry := range sr.Entries {
		if host := c.hostnameFromEntry(entry); host != "" {
			computers = append(computers, host)
		}
	}

	return computers, nil
}

// GetServers retrieves server objects from AD (computers with "server" in OS) using paging.
func (c *Client) GetServers() ([]string, error) {
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=computer)(objectClass=computer)(operatingSystem=*server*))",
		[]string{"dNSHostName", "name"},
		nil,
	)

	// Use paging to handle large result sets
	sr, err := c.conn.SearchWithPaging(searchRequest, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var servers []string
	for _, entry := range sr.Entries {
		if host := c.hostnameFromEntry(entry); host != "" {
			servers = append(servers, host)
		}
	}

	return servers, nil
}

// hostnameFromEntry returns dNSHostName if set, otherwise falls back to the
// name attribute. If the resulting value is a bare hostname (no dot), the AD
// domain is appended so the targets loader accepts it as an FQDN. Returns ""
// if neither attribute is available.
func (c *Client) hostnameFromEntry(entry *ldap.Entry) string {
	host := entry.GetAttributeValue("dNSHostName")
	if host == "" {
		host = entry.GetAttributeValue("name")
	}
	if host == "" {
		return ""
	}
	if strings.Contains(host, ".") || c.domain == "" {
		return host
	}
	return host + "." + c.domain
}

// GetSubnets retrieves subnet objects from AD Sites and Services.
func (c *Client) GetSubnets() ([]string, error) {
	// Subnets are stored in CN=Subnets,CN=Sites,CN=Configuration,<baseDN>
	configDN := "CN=Subnets,CN=Sites,CN=Configuration," + c.baseDN

	searchRequest := ldap.NewSearchRequest(
		configDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=subnet)",
		[]string{"cn", "name"},
		nil,
	)

	// Use paging for consistency, though subnets are usually fewer
	sr, err := c.conn.SearchWithPaging(searchRequest, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for subnets failed: %w", err)
	}

	var subnets []string
	for _, entry := range sr.Entries {
		// The CN of a subnet object is the CIDR notation (e.g., "10.0.0.0/24")
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			subnets = append(subnets, cn)
		}
	}

	return subnets, nil
}

// domainToBaseDN converts a domain name to LDAP base DN.
// e.g., "corp.local" -> "DC=corp,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, "DC="+part)
	}
	return strings.Join(dnParts, ",")
}
