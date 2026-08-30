// Package credentials handles authentication credentials for SMB connections.
package credentials

import (
	"encoding/hex"
	"regexp"
	"strings"
)

// Credentials holds authentication information for SMB connections.
type Credentials struct {
	// Identity
	Domain   string
	Username string
	Password string

	// Hashes for pass-the-hash authentication
	NTHex string
	NTRaw []byte
	LMHex string
	LMRaw []byte

	// Kerberos authentication
	UseKerberos bool
	WindowsAuth bool
	AESKey      string
	KDCHost     string
}

// NewCredentials creates a new Credentials instance.
func NewCredentials(domain, username, password string, hashes *string, useKerberos, windowsAuth bool, aesKey, kdcHost *string) *Credentials {
	c := &Credentials{
		Domain:      domain,
		Username:    username,
		Password:    password,
		UseKerberos: useKerberos,
		WindowsAuth: windowsAuth,
	}

	if aesKey != nil {
		c.AESKey = *aesKey
	}
	if kdcHost != nil {
		c.KDCHost = *kdcHost
	}
	if hashes != nil {
		c.SetHashes(*hashes)
	}

	return c
}

// SetHashes parses and sets the LM and NT hashes from a string in "LM:NT" format.
func (c *Credentials) SetHashes(hashes string) {
	c.LMHex = ""
	c.LMRaw = nil
	c.NTHex = ""
	c.NTRaw = nil

	if hashes == "" {
		return
	}

	lm, nt := ParseLMNTHashes(hashes)
	c.LMHex = lm
	c.NTHex = nt

	if c.LMHex != "" {
		c.LMRaw, _ = hex.DecodeString(c.LMHex)
	}
	if c.NTHex != "" {
		c.NTRaw, _ = hex.DecodeString(c.NTHex)
	}
}

// IsAnonymous returns true if no username is provided.
func (c *Credentials) IsAnonymous() bool {
	return c.Username == ""
}

// CanPassTheHash returns true if both LM and NT hashes are available.
func (c *Credentials) CanPassTheHash() bool {
	return c.NTHex != "" && len(c.NTRaw) > 0 && c.LMHex != "" && len(c.LMRaw) > 0
}

// HasHashes returns true if NT hash is available.
func (c *Credentials) HasHashes() bool {
	return c.NTHex != "" && len(c.NTRaw) > 0
}

// ParseLMNTHashes parses a string containing LM and NT hash values.
// The format is "LM:NT" or ":NT" or "LM:".
// Returns the LM and NT hash values as separate strings.
func ParseLMNTHashes(hashString string) (lmHash, ntHash string) {
	if hashString == "" {
		return "", ""
	}

	// Pattern: optional 32-char hex, optional colon, optional 32-char hex
	pattern := regexp.MustCompile(`(?i)^([0-9a-f]{32})?(:)?([0-9a-f]{32})?$`)
	matches := pattern.FindStringSubmatch(strings.TrimSpace(strings.ToLower(hashString)))

	if matches == nil || len(matches) < 4 {
		return "", ""
	}

	mLMHash := matches[1]
	mSep := matches[2]
	mNTHash := matches[3]

	// No hash found
	if mLMHash == "" && mSep == "" && mNTHash == "" {
		return "", ""
	}

	// Only NT hash provided (e.g., ":aabbccdd...")
	if mLMHash == "" && mNTHash != "" {
		return "aad3b435b51404eeaad3b435b51404ee", mNTHash
	}

	// Only LM hash provided (e.g., "aabbccdd...:")
	if mLMHash != "" && mNTHash == "" {
		return mLMHash, "31d6cfe0d16ae931b73c59d7e0c089c0"
	}

	return mLMHash, mNTHash
}

// String returns a string representation of the credentials.
func (c *Credentials) String() string {
	return "<Credentials for '" + c.Domain + "\\" + c.Username + "'>"
}
