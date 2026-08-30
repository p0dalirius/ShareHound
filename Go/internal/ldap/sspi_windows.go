//go:build windows

package ldap

import (
	"crypto/x509"

	ldapv3 "github.com/go-ldap/ldap/v3"
	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
)

func newWindowsGSSAPIClient(tlsServerCert *x509.Certificate) (ldapv3.GSSAPIClient, error) {
	if tlsServerCert != nil {
		return ldapgssapi.NewSSPIClientWithChannelBinding(tlsServerCert)
	}
	return ldapgssapi.NewSSPIClient()
}
