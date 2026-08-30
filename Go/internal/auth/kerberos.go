// Package auth provides shared authentication helpers.
package auth

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	krbcredentials "github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// KerberosOptions describes the credential material used to build a Kerberos client.
type KerberosOptions struct {
	Domain     string
	Username   string
	Password   string
	KeytabPath string
	KDCHost    string
}

// NewKerberosClient creates and logs in a gokrb5 client using password, keytab, or KRB5CCNAME.
func NewKerberosClient(opts KerberosOptions) (*krbclient.Client, error) {
	realm, username := SplitPrincipal(opts.Domain, opts.Username)
	cfg, err := LoadKerberosConfig(realm, opts.Domain, opts.KDCHost)
	if err != nil {
		return nil, err
	}

	if opts.KeytabPath != "" {
		kt, err := keytab.Load(opts.KeytabPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load Kerberos keytab %q: %w", opts.KeytabPath, err)
		}
		if username == "" {
			return nil, fmt.Errorf("--auth-user is required with --auth-key when using Kerberos keytab authentication")
		}
		client := krbclient.NewWithKeytab(username, realm, kt, cfg)
		if err := client.Login(); err != nil {
			return nil, fmt.Errorf("Kerberos keytab login failed: %w", err)
		}
		return client, nil
	}

	if ccachePath := credentialCachePath(); ccachePath != "" && opts.Password == "" {
		ccache, err := krbcredentials.LoadCCache(ccachePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load Kerberos credential cache %q: %w", ccachePath, err)
		}
		client, err := krbclient.NewFromCCache(ccache, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kerberos client from credential cache: %w", err)
		}
		return client, nil
	}

	if username == "" || opts.Password == "" {
		return nil, fmt.Errorf("Kerberos authentication requires --auth-user with --auth-password, --auth-key as a keytab path, or KRB5CCNAME")
	}

	client := krbclient.NewWithPassword(username, realm, opts.Password, cfg)
	if err := client.Login(); err != nil {
		return nil, fmt.Errorf("Kerberos password login failed: %w", err)
	}
	return client, nil
}

// LoadKerberosConfig loads KRB5_CONFIG when present, otherwise builds a minimal AD realm config.
func LoadKerberosConfig(realm, domain, kdcHost string) (*krbconfig.Config, error) {
	if path := kerberosConfigPath(); path != "" {
		return krbconfig.Load(path)
	}

	cfg := krbconfig.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = kdcHost == ""
	cfg.LibDefaults.DNSLookupRealm = kdcHost == ""
	cfg.LibDefaults.RDNS = false
	cfg.LibDefaults.UDPPreferenceLimit = 1

	if kdcHost != "" {
		kdc := withDefaultPort(kdcHost, "88")
		admin := withDefaultPort(kdcHost, "749")
		kpasswd := withDefaultPort(kdcHost, "464")
		cfg.Realms = []krbconfig.Realm{{
			Realm:         realm,
			KDC:           []string{kdc},
			AdminServer:   []string{admin},
			KPasswdServer: []string{kpasswd},
		}}
	}

	if cfg.DomainRealm == nil {
		cfg.DomainRealm = make(krbconfig.DomainRealm)
	}
	if domain != "" {
		lowerDomain := strings.ToLower(domain)
		cfg.DomainRealm[lowerDomain] = realm
		cfg.DomainRealm["."+lowerDomain] = realm
	}

	return cfg, nil
}

// SplitPrincipal returns a Kerberos realm and username from ShareHound's domain/user flags.
func SplitPrincipal(domain, username string) (string, string) {
	realm := NormalizeRealm(domain)
	user := username

	if idx := strings.Index(user, `\`); idx >= 0 {
		realm = NormalizeRealm(user[:idx])
		user = user[idx+1:]
	}
	if idx := strings.LastIndex(user, "@"); idx > 0 {
		realm = NormalizeRealm(user[idx+1:])
		user = user[:idx]
	}

	return realm, user
}

// NormalizeRealm converts a Windows domain value into a Kerberos realm.
func NormalizeRealm(domain string) string {
	return strings.ToUpper(strings.TrimSpace(domain))
}

// ServicePrincipal builds a Kerberos service principal such as cifs/server.example.com.
func ServicePrincipal(service, host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = strings.Trim(parsedHost, "[]")
	}
	return strings.ToLower(service) + "/" + host
}

func kerberosConfigPath() string {
	if path := os.Getenv("KRB5_CONFIG"); path != "" {
		return path
	}
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(`C:\Windows\krb5.ini`); err == nil {
			return `C:\Windows\krb5.ini`
		}
		return ""
	}
	if _, err := os.Stat("/etc/krb5.conf"); err == nil {
		return "/etc/krb5.conf"
	}
	return ""
}

func credentialCachePath() string {
	path := os.Getenv("KRB5CCNAME")
	path = strings.TrimPrefix(path, "FILE:")
	path = strings.TrimPrefix(path, "file:")
	return path
}

func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.Contains(host, ":") && strings.Count(host, ":") > 1 {
		return "[" + strings.Trim(host, "[]") + "]:" + port
	}
	return host + ":" + port
}
