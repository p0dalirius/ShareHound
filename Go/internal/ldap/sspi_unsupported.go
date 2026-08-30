//go:build !windows

package ldap

import (
	"crypto/x509"
	"fmt"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

func newWindowsGSSAPIClient(_ *x509.Certificate) (ldapv3.GSSAPIClient, error) {
	return nil, fmt.Errorf("implicit Windows authentication is only supported on Windows")
}
