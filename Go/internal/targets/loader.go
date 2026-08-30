// Package targets provides target enumeration functionality.
package targets

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/ldap"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/utils"
)

// Target represents a scan target.
type Target struct {
	Type  string // "ipv4", "ipv6", "fqdn"
	Value string
}

// Options holds target loading options.
type Options struct {
	TargetsFile  string
	Targets      []string
	AuthDomain   string
	AuthDCIP     string
	AuthUser     string
	AuthPassword string
	AuthHashes   string
	AuthKey      string
	UseKerberos  bool
	WindowsAuth  bool
	KDCHost      string
	UseLDAPS     bool
	Subnets      bool
	Timeout      time.Duration
}

// LoadTargets loads and parses targets from various sources.
func LoadTargets(opts *Options, cfg *config.Config, log logger.LoggerInterface) ([]Target, error) {
	var rawTargets []string

	// Check if DC is reachable for LDAP queries
	if opts.AuthDCIP != "" && opts.hasLDAPAuth() {
		port := 389
		if opts.UseLDAPS {
			port = 636
		}
		ok, _ := utils.IsPortOpen(opts.AuthDCIP, port, 10*time.Second)
		if !ok {
			log.Error(fmt.Sprintf("Domain controller %s is not reachable on port %d", opts.AuthDCIP, port))
			return nil, nil
		}
	}

	// Load from file
	if opts.TargetsFile != "" {
		log.Debug("Loading targets from file: " + opts.TargetsFile)
		fileTargets, err := loadFromFile(opts.TargetsFile)
		if err != nil {
			log.Error("Error loading targets file: " + err.Error())
		} else {
			rawTargets = append(rawTargets, fileTargets...)
		}
	}

	// Load from CLI options
	if len(opts.Targets) > 0 {
		log.Debug("Loading targets from CLI options")
		rawTargets = append(rawTargets, opts.Targets...)
	}

	// Load from AD if no explicit targets
	if len(rawTargets) == 0 && opts.AuthDCIP != "" && opts.hasLDAPAuth() {
		log.Info(fmt.Sprintf("No target list specified, fetching all computers from Active Directory domain '%s'", opts.AuthDomain))

		adTargets, err := loadFromActiveDirectory(opts, log)
		if err != nil {
			log.Error("Error loading targets from Active Directory: " + err.Error())
		} else {
			rawTargets = append(rawTargets, adTargets...)
		}
	}

	// Load subnets if requested
	if opts.Subnets && opts.AuthDCIP != "" && opts.hasLDAPAuth() {
		log.Debug(fmt.Sprintf("Loading subnets from domain '%s'", opts.AuthDomain))
		subnets, err := loadSubnetsFromAD(opts, log)
		if err != nil {
			log.Warning("Error loading subnets from AD: " + err.Error())
		} else {
			rawTargets = append(rawTargets, subnets...)
		}
	}

	// Deduplicate and sort
	rawTargets = uniqueStrings(rawTargets)

	// Parse and classify targets
	var finalTargets []Target
	for _, t := range rawTargets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		if utils.IsIPv4CIDR(t) {
			// Expand CIDR
			ips, err := utils.ExpandCIDR(t)
			if err != nil {
				log.Debug("Error expanding CIDR " + t + ": " + err.Error())
				continue
			}
			for _, ip := range ips {
				finalTargets = append(finalTargets, Target{Type: "ipv4", Value: ip})
			}
		} else if utils.IsIPv4Addr(t) {
			finalTargets = append(finalTargets, Target{Type: "ipv4", Value: t})
		} else if utils.IsIPv6Addr(t) {
			finalTargets = append(finalTargets, Target{Type: "ipv6", Value: t})
		} else if utils.IsFQDN(t) {
			finalTargets = append(finalTargets, Target{Type: "fqdn", Value: t})
		} else {
			log.Debug("Target '" + t + "' was not added (unknown type)")
		}
	}

	// Deduplicate final targets
	finalTargets = uniqueTargets(finalTargets)

	return finalTargets, nil
}

func (opts *Options) hasLDAPAuth() bool {
	if opts.WindowsAuth {
		return true
	}
	if opts.AuthUser != "" && (opts.AuthPassword != "" || opts.AuthHashes != "" || opts.AuthKey != "" || opts.UseKerberos) {
		return true
	}
	return opts.UseKerberos && os.Getenv("KRB5CCNAME") != ""
}

// loadFromActiveDirectory loads computers and servers from AD.
func loadFromActiveDirectory(opts *Options, log logger.LoggerInterface) ([]string, error) {
	ldapOpts := &ldap.ClientOptions{
		Domain:      opts.AuthDomain,
		DCIP:        opts.AuthDCIP,
		Username:    opts.AuthUser,
		Password:    opts.AuthPassword,
		Hashes:      opts.AuthHashes,
		AuthKey:     opts.AuthKey,
		UseLDAPS:    opts.UseLDAPS,
		UseKerberos: opts.UseKerberos,
		WindowsAuth: opts.WindowsAuth,
		KDCHost:     opts.KDCHost,
	}

	client, err := ldap.NewClient(ldapOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create LDAP client: %w", err)
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer client.Close()

	var targets []string

	// Get computers
	log.Debug("Loading targets from computers in the domain")
	computers, err := client.GetComputers()
	if err != nil {
		log.Warning("Error fetching computers: " + err.Error())
	} else {
		log.Info(fmt.Sprintf("Found %d computers in Active Directory", len(computers)))
		targets = append(targets, computers...)
	}

	// Get servers
	log.Debug("Loading targets from servers in the domain")
	servers, err := client.GetServers()
	if err != nil {
		log.Warning("Error fetching servers: " + err.Error())
	} else {
		log.Info(fmt.Sprintf("Found %d servers in Active Directory", len(servers)))
		targets = append(targets, servers...)
	}

	return targets, nil
}

// loadSubnetsFromAD loads subnet CIDRs from AD Sites and Services.
func loadSubnetsFromAD(opts *Options, log logger.LoggerInterface) ([]string, error) {
	ldapOpts := &ldap.ClientOptions{
		Domain:      opts.AuthDomain,
		DCIP:        opts.AuthDCIP,
		Username:    opts.AuthUser,
		Password:    opts.AuthPassword,
		Hashes:      opts.AuthHashes,
		AuthKey:     opts.AuthKey,
		UseLDAPS:    opts.UseLDAPS,
		UseKerberos: opts.UseKerberos,
		WindowsAuth: opts.WindowsAuth,
		KDCHost:     opts.KDCHost,
	}

	client, err := ldap.NewClient(ldapOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create LDAP client: %w", err)
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer client.Close()

	subnets, err := client.GetSubnets()
	if err != nil {
		return nil, fmt.Errorf("failed to get subnets: %w", err)
	}

	log.Info(fmt.Sprintf("Found %d subnets in Active Directory", len(subnets)))
	return subnets, nil
}

// loadFromFile loads targets from a file, one per line.
func loadFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

// uniqueStrings returns unique strings sorted.
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	sort.Strings(result)
	return result
}

// uniqueTargets returns unique targets sorted.
func uniqueTargets(input []Target) []Target {
	seen := make(map[string]bool)
	var result []Target
	for _, t := range input {
		key := t.Type + ":" + t.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, t)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].Value < result[j].Value
	})
	return result
}
