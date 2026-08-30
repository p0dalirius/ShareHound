// ShareHound - A tool to map network share access rights into BloodHound OpenGraph format.
// Original Python version by Remi Gascou (@podalirius_) @ SpecterOps
// Go port by Javier Azofra @ Siemens Healthineers
package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/specterops/sharehound/internal/checkpoint"
	"github.com/specterops/sharehound/internal/collector"
	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/credentials"
	"github.com/specterops/sharehound/internal/graph"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/rules"
	"github.com/specterops/sharehound/internal/status"
	"github.com/specterops/sharehound/internal/targets"
	"github.com/specterops/sharehound/internal/utils"
	"github.com/specterops/sharehound/internal/worker"
	"github.com/specterops/sharehound/pkg/kinds"
)

// Version information
const Version = "2.0.0-go"

// CLI flags
var (
	// Output options
	verbose  bool
	debug    bool
	noColors bool
	logfile  string
	output   string

	// Advanced configuration
	advertisedName    string
	threads           int
	maxWorkersPerHost int
	globalMaxWorkers  int
	nameserver        string
	timeout           float64
	hostTimeout       float64

	// Rules
	rulesFiles  []string
	ruleStrings []string

	// Share exploration
	shareName           string
	depth               int
	includeCommonShares bool

	// Targets and authentication
	targetsFile  string
	targetsList  []string
	authDomain   string
	authDCIP     string
	authUser     string
	authPassword string
	authHashes   string
	authKey      string
	useKerberos  bool
	windowsAuth  bool
	kdcHost      string
	useLDAPS     bool
	subnets      bool

	// Checkpoint/resume options
	checkpointFile     string
	checkpointInterval float64
	resume             bool

	// Output filtering
	effectiveAccessOnly bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sharehound",
		Short: "ShareHound - Map network share access rights to BloodHound OpenGraph",
		Long: `ShareHound is a tool that enumerates SMB shares and their permissions,
creating a BloodHound-compatible OpenGraph for security analysis.`,
		Run:     run,
		Version: Version,
	}

	// Output options
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose mode")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Debug mode")
	rootCmd.Flags().BoolVar(&noColors, "no-colors", false, "Disable ANSI escape codes")
	rootCmd.Flags().StringVar(&logfile, "logfile", "", "Log file to write to")
	rootCmd.Flags().StringVarP(&output, "output", "o", "opengraph.zip", "Output file (use .zip extension for compression)")

	// Advanced configuration
	rootCmd.Flags().StringVar(&advertisedName, "advertised-name", "", "Advertised name of the client")
	rootCmd.Flags().IntVar(&threads, "threads", runtime.NumCPU()*8, "Number of threads to use")
	rootCmd.Flags().IntVar(&maxWorkersPerHost, "max-workers-per-host", 8, "Maximum concurrent shares per host")
	rootCmd.Flags().IntVar(&globalMaxWorkers, "global-max-workers", 200, "Global maximum workers")
	rootCmd.Flags().StringVarP(&nameserver, "nameserver", "n", "", "Nameserver for DNS queries")
	rootCmd.Flags().Float64VarP(&timeout, "timeout", "t", 2.5, "Timeout in seconds for network operations")
	rootCmd.Flags().Float64Var(&hostTimeout, "host-timeout", 0, "Maximum time in minutes per host (0 = no limit)")

	// Rules
	rootCmd.Flags().StringArrayVarP(&rulesFiles, "rules-file", "r", nil, "Path to file containing rules")
	rootCmd.Flags().StringArrayVar(&ruleStrings, "rule-string", nil, "Rule string (can be specified multiple times)")

	// Share exploration
	rootCmd.Flags().StringVar(&shareName, "share", "", "Share to enumerate (default: all shares)")
	rootCmd.Flags().IntVar(&depth, "depth", 0, "Maximum depth to traverse directories (0 = unlimited)")
	rootCmd.Flags().BoolVar(&includeCommonShares, "include-common-shares", false, "Include C$, ADMIN$, IPC$, PRINT$")

	// Targets and authentication
	rootCmd.Flags().StringVarP(&targetsFile, "targets-file", "f", "", "Path to file containing targets")
	rootCmd.Flags().StringArrayVar(&targetsList, "target", nil, "Target IP, FQDN or CIDR")
	rootCmd.Flags().StringVar(&authDomain, "auth-domain", "", "Windows domain to authenticate to")
	rootCmd.Flags().StringVar(&authDCIP, "auth-dc-ip", "", "IP of the domain controller")
	rootCmd.Flags().StringVar(&authUser, "auth-user", "", "Username of the domain account")
	rootCmd.Flags().StringVar(&authPassword, "auth-password", "", "Password of the domain account")
	rootCmd.Flags().StringVar(&authHashes, "auth-hashes", "", "LM:NT hashes for pass-the-hash")
	rootCmd.Flags().StringVar(&authKey, "auth-key", "", "Kerberos keytab path for authentication")
	rootCmd.Flags().BoolVarP(&useKerberos, "use-kerberos", "k", false, "Use Kerberos authentication")
	rootCmd.Flags().BoolVar(&windowsAuth, "windows-auth", false, "Use current Windows credentials with Kerberos SSPI authentication")
	rootCmd.Flags().StringVar(&kdcHost, "kdc-host", "", "KDC host for Kerberos authentication")
	rootCmd.Flags().BoolVar(&useLDAPS, "ldaps", false, "Use LDAPS instead of LDAP")
	rootCmd.Flags().BoolVar(&subnets, "subnets", false, "Auto-enumerate all domain subnets")

	// Checkpoint/resume options
	rootCmd.Flags().StringVar(&checkpointFile, "checkpoint", "", "Checkpoint file for resumable scans")
	rootCmd.Flags().Float64Var(&checkpointInterval, "checkpoint-interval", 60, "Checkpoint save interval in seconds")
	rootCmd.Flags().BoolVar(&resume, "resume", false, "Resume from existing checkpoint file")

	// Output filtering
	rootCmd.Flags().BoolVar(&effectiveAccessOnly, "effective-access-only", false, "Only emit CanEffectiveRead/Write/Execute edges for files and directories (reduces edge count)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	fmt.Printf("ShareHound v%s - Original by Remi Gascou (@podalirius_) @ SpecterOps, Go port by Javier Azofra @ Siemens Healthineers\n\n", Version)

	// Validate arguments
	if targetsFile == "" && len(targetsList) == 0 && authUser == "" && !windowsAuth && !(useKerberos && os.Getenv("KRB5CCNAME") != "") {
		fmt.Println("[!] No targets specified. Either provide targets with --target or --targets-file,")
		fmt.Println("    or provide AD credentials (--auth-dc-ip, --auth-user, --auth-password), --use-kerberos with KRB5CCNAME, or --windows-auth")
		os.Exit(1)
	}

	if authPassword != "" && authHashes != "" {
		fmt.Println("[!] Options --auth-password and --auth-hashes are mutually exclusive.")
		os.Exit(1)
	}

	if windowsAuth && (authUser != "" || authPassword != "" || authHashes != "" || authKey != "") {
		fmt.Println("[!] Option --windows-auth uses the current Windows logon session and cannot be combined with explicit credentials.")
		os.Exit(1)
	}

	if windowsAuth {
		useKerberos = true
		if authDomain == "" {
			authDomain = os.Getenv("USERDNSDOMAIN")
		}
	}

	if targetsFile == "" && len(targetsList) == 0 && (windowsAuth || useKerberos) && authDCIP == "" {
		fmt.Println("[!] Option --auth-dc-ip is required when loading targets from Active Directory with Kerberos or Windows auth.")
		os.Exit(1)
	}

	if targetsFile == "" && len(targetsList) == 0 && authDomain == "" {
		fmt.Println("[!] Option --auth-domain is required when loading targets from Active Directory.")
		os.Exit(1)
	}

	if authDCIP == "" && authUser != "" && (authPassword != "" || authHashes != "") {
		fmt.Println("[!] Option --auth-dc-ip is required when using authentication options.")
		os.Exit(1)
	}

	// Create configuration
	cfg := config.NewConfig(debug, &noColors)

	// Create logger
	log := logger.NewLogger(cfg, logfile)
	defer log.Close()

	// Parse rules
	var parsedRules []rules.Rule
	parser := rules.NewParser()

	if len(rulesFiles) == 0 && len(ruleStrings) == 0 {
		// Use default rules
		ruleStrings = rules.DefaultRules
	}

	if len(rulesFiles) > 0 {
		for _, file := range rulesFiles {
			content, err := os.ReadFile(file)
			if err != nil {
				log.Error(fmt.Sprintf("Error reading rules file %s: %v", file, err))
				os.Exit(1)
			}
			fileRules, errors := parser.Parse(string(content))
			if len(errors) > 0 {
				log.Error(fmt.Sprintf("Errors parsing rules file %s:", file))
				for _, e := range errors {
					log.Error(e.Error())
				}
				os.Exit(1)
			}
			parsedRules = append(parsedRules, fileRules...)
		}
	} else if len(ruleStrings) > 0 {
		rules, errors := parser.ParseStrings(ruleStrings)
		if len(errors) > 0 {
			log.Error("Errors parsing rules:")
			for _, e := range errors {
				log.Error(e.Error())
			}
			os.Exit(1)
		}
		parsedRules = rules
	}

	log.Debug(fmt.Sprintf("%d rules parsed successfully", len(parsedRules)))

	log.Info("Starting ShareHound")
	startTime := time.Now()

	// Create OpenGraph
	og, err := graph.NewOpenGraph(kinds.NodeKindNetworkShareBase)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to create graph: %v", err))
		os.Exit(1)
	}
	defer og.Close()

	// Create checkpoint manager
	cpInterval := time.Duration(checkpointInterval * float64(time.Second))
	cpManager := checkpoint.NewManager(checkpointFile, cpInterval)

	// Handle resume
	if resume && checkpointFile != "" {
		if checkpoint.Exists(checkpointFile) {
			log.Info(fmt.Sprintf("Resuming from checkpoint: %s", checkpointFile))
			cp, err := checkpoint.Load(checkpointFile)
			if err != nil {
				log.Error(fmt.Sprintf("Failed to load checkpoint: %v", err))
				os.Exit(1)
			}
			cpManager.RestoreFrom(cp)
			og.RestoreNodesAndEdges(cp.GraphNodes, cp.GraphEdges)
			log.Info(fmt.Sprintf("Restored %d processed targets, %d nodes, %d edges",
				len(cp.ProcessedTargets), len(cp.GraphNodes), len(cp.GraphEdges)))
		} else {
			log.Warning("Checkpoint file not found, starting fresh scan")
		}
	}

	// Load targets
	targetOpts := &targets.Options{
		TargetsFile:  targetsFile,
		Targets:      targetsList,
		AuthDomain:   authDomain,
		AuthDCIP:     authDCIP,
		AuthUser:     authUser,
		AuthPassword: authPassword,
		AuthHashes:   authHashes,
		AuthKey:      authKey,
		UseKerberos:  useKerberos,
		WindowsAuth:  windowsAuth,
		KDCHost:      kdcHost,
		UseLDAPS:     useLDAPS,
		Subnets:      subnets,
		Timeout:      time.Duration(timeout * float64(time.Second)),
	}

	loadedTargets, err := targets.LoadTargets(targetOpts, cfg, log)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to load targets: %v", err))
		os.Exit(1)
	}

	log.Info(fmt.Sprintf("Targeting %d hosts", len(loadedTargets)))

	if len(loadedTargets) == 0 {
		log.Warning("No targets to scan")
		os.Exit(0)
	}

	// Create credentials
	creds := credentials.NewCredentials(
		authDomain,
		authUser,
		authPassword,
		&authHashes,
		useKerberos,
		windowsAuth,
		&authKey,
		&kdcHost,
	)

	// Create worker options
	workerOpts := &worker.Options{
		Creds:               creds,
		Timeout:             time.Duration(timeout * float64(time.Second)),
		HostTimeout:         time.Duration(hostTimeout * float64(time.Minute)),
		AdvertisedName:      advertisedName,
		MaxWorkersPerHost:   maxWorkersPerHost,
		GlobalMaxWorkers:    globalMaxWorkers,
		Depth:               depth,
		Nameserver:          nameserver,
		Logfile:             logfile,
		EffectiveAccessOnly: effectiveAccessOnly,
	}

	// Debug: show host timeout value
	if workerOpts.HostTimeout > 0 {
		log.Info(fmt.Sprintf("Host timeout enabled: %v per host", workerOpts.HostTimeout))
	}

	// Create results tracker
	results := &collector.WorkerResults{}
	var resultsLock sync.Mutex

	// Filter out already-processed targets if resuming
	var targetsToProcess []targets.Target
	skippedCount := 0
	for _, target := range loadedTargets {
		if cpManager.IsTargetProcessed(target) {
			skippedCount++
			continue
		}
		targetsToProcess = append(targetsToProcess, target)
	}

	if skippedCount > 0 {
		log.Info(fmt.Sprintf("Skipping %d already-processed targets, %d remaining",
			skippedCount, len(targetsToProcess)))
	}

	// Start progress tracker
	tracker := status.NewProgressTracker(results, &resultsLock, len(loadedTargets))
	tracker.Start()

	// Start checkpoint manager
	getStats := func() checkpoint.Statistics {
		resultsLock.Lock()
		defer resultsLock.Unlock()
		return checkpoint.Statistics{
			Success:              results.Success,
			Errors:               results.Errors,
			SharesTotal:          results.SharesTotal,
			SharesProcessed:      results.SharesProcessed,
			FilesTotal:           results.FilesTotal,
			FilesProcessed:       results.FilesProcessed,
			DirectoriesTotal:     results.DirectoriesTotal,
			DirectoriesProcessed: results.DirectoriesProcessed,
		}
	}
	cpManager.Start(og, len(loadedTargets), getStats)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	stopChan := make(chan struct{})

	go func() {
		sig := <-sigChan
		log.Warning(fmt.Sprintf("Received signal %v, saving checkpoint and shutting down...", sig))
		cpManager.TriggerSave()
		close(stopChan)
	}()

	// Process targets concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)

	for _, target := range targetsToProcess {
		// Check for stop signal
		select {
		case <-stopChan:
			log.Info("Stop signal received, waiting for current tasks to complete...")
			break
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(t targets.Target) {
			defer wg.Done()
			defer func() { <-semaphore }()

			worker.ProcessTarget(t, workerOpts, cfg, og, parsedRules, results, &resultsLock)
			cpManager.MarkTargetProcessed(t)
		}(target)
	}

	wg.Wait()
	tracker.Stop()

	fmt.Println() // blank line after progress bar
	scanElapsed := time.Since(startTime)
	fmt.Printf("[*] Scan phase completed in %s\n", utils.DeltaTime(scanElapsed))

	// --- Post-scan phase with step-by-step visibility ---
	fmt.Printf("[*] Stopping checkpoint manager...\n")
	cpManager.Stop()
	fmt.Printf("[+] Checkpoint manager stopped\n")

	// Export graph with progress
	nodeCount := og.GetNodeCount()
	edgeCount := og.GetEdgeCount()
	fmt.Printf("[*] Exporting graph to \"%s\" (%d nodes, %d edges)...\n", output, nodeCount, edgeCount)

	log.Info(fmt.Sprintf("Exporting graph to \"%s\"", output))
	log.IncrementIndent()
	log.Info(fmt.Sprintf("Nodes: %d", nodeCount))
	log.Info(fmt.Sprintf("Edges: %d", edgeCount))

	exportStart := time.Now()
	lastProgressLine := ""

	exportProgress := func(phase string, current, total int) {
		var line string
		if total > 0 {
			pct := float64(current) / float64(total) * 100
			line = fmt.Sprintf("\r\033[K    [%s] %d/%d (%.1f%%)", phase, current, total, pct)
		} else {
			line = fmt.Sprintf("\r\033[K    [%s]", phase)
		}
		if line != lastProgressLine {
			fmt.Print(line)
			lastProgressLine = line
		}
	}

	if err := og.ExportToFileWithProgress(output, true, exportProgress); err != nil {
		fmt.Println() // ensure newline after progress
		log.Error(fmt.Sprintf("Failed to export graph: %v", err))
		os.Exit(1)
	}
	fmt.Println() // newline after last progress update

	exportElapsed := time.Since(exportStart)

	// Get file size
	info, _ := os.Stat(output)
	fmt.Printf("[+] Graph exported to \"%s\" (%s) in %s\n", output, utils.FormatFileSize(info.Size()), utils.DeltaTime(exportElapsed))
	log.Info(fmt.Sprintf("Graph successfully exported to \"%s\" (%s)", output, utils.FormatFileSize(info.Size())))
	log.DecrementIndent()

	// Print final summary
	status.PrintFinalSummary(results, &resultsLock)

	// Clean up checkpoint file on successful completion
	if cpManager.IsEnabled() && len(targetsToProcess) == 0 || cpManager.GetProcessedCount() == len(loadedTargets) {
		fmt.Printf("[*] Cleaning up checkpoint file...\n")
		if err := checkpoint.Delete(cpManager.GetFilepath()); err == nil {
			log.Info("Checkpoint file cleaned up (scan completed successfully)")
			fmt.Printf("[+] Checkpoint file cleaned up\n")
		}
	} else if cpManager.IsEnabled() {
		log.Info(fmt.Sprintf("Checkpoint saved to %s (use --resume to continue)", cpManager.GetFilepath()))
		fmt.Printf("[*] Checkpoint saved to %s (use --resume to continue)\n", cpManager.GetFilepath())
	}

	elapsed := time.Since(startTime)
	log.Info(fmt.Sprintf("ShareHound completed, time elapsed: %s", utils.DeltaTime(elapsed)))
	fmt.Printf("[+] ShareHound completed, total time: %s\n", utils.DeltaTime(elapsed))
}
