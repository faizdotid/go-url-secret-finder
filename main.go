// Package main implements a concurrent URL scanner that matches response bodies
// against configurable regex patterns and records matches to output files.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ANSI color codes for terminal output.
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorWhite  = "\033[37m"
	colorReset  = "\033[0m"
)

// Default configuration values.
const (
	defaultThreads      = 0 // Will use runtime.NumCPU()
	defaultTimeout      = 10
	defaultMaxRedirects = 10
	defaultBufferSize   = 1000
	defaultConfigFile   = "config.json"
	defaultResultsDir   = "results"
	maxBodySize         = 10 * 1024 * 1024 // 10MB
	maxURLLength        = 1024 * 1024      // 1MB buffer for scanner
)

// ScanConfig represents a single scanning configuration with name, regex pattern,
// and output file destination.
type ScanConfig struct {
	Name    string `json:"name"`
	Regex   string `json:"regex"`
	Outfile string `json:"outfile"`
}

// Stats holds scanning statistics using atomic operations for thread safety.
type Stats struct {
	TotalScanned   int64
	TotalMatches   int64
	TotalErrors    int64
	TotalNoMatches int64
}

// URLScanner is the main scanner that processes URLs concurrently.
type URLScanner struct {
	configs    []ScanConfig
	client     *http.Client
	verbose    bool
	matchOnly  bool
	patterns   map[string]*regexp.Regexp
	fileMutex  map[string]*sync.Mutex
	stats      *Stats
	resultsDir string
	mu         sync.RWMutex // Protects fileMutex map
}

// Config holds command-line configuration.
type Config struct {
	FileName     string
	ConfigFile   string
	ResultsDir   string
	Threads      int
	Timeout      int
	MaxRedirects int
	BufferSize   int
	Verbose      bool
	MatchOnly    bool
}

// loadScanConfigs reads and parses the JSON configuration file.
func loadScanConfigs(filename string) ([]ScanConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", filename, err)
	}

	var configs []ScanConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("parsing config JSON: %w", err)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no scan configurations found in %s", filename)
	}

	return configs, nil
}

// NewURLScanner creates and initializes a new URLScanner instance.
func NewURLScanner(configs []ScanConfig, client *http.Client, verbose, matchOnly bool, resultsDir string) (*URLScanner, error) {
	scanner := &URLScanner{
		configs:    configs,
		client:     client,
		verbose:    verbose,
		matchOnly:  matchOnly,
		patterns:   make(map[string]*regexp.Regexp, len(configs)),
		fileMutex:  make(map[string]*sync.Mutex),
		stats:      &Stats{},
		resultsDir: resultsDir,
	}

	if err := scanner.initPatterns(); err != nil {
		return nil, err
	}

	return scanner, nil
}

// initPatterns compiles all regex patterns from the configuration.
func (s *URLScanner) initPatterns() error {
	for _, cfg := range s.configs {
		if cfg.Regex == "" {
			return fmt.Errorf("empty regex for config %q", cfg.Name)
		}

		pattern, err := regexp.Compile(cfg.Regex)
		if err != nil {
			return fmt.Errorf("compiling regex for %q: %w", cfg.Name, err)
		}

		s.patterns[cfg.Name] = pattern
		s.fileMutex[cfg.Outfile] = &sync.Mutex{}
	}

	return nil
}

// getMutex returns the mutex for a given output file, creating one if necessary.
func (s *URLScanner) getMutex(outfile string) *sync.Mutex {
	s.mu.RLock()
	mu, exists := s.fileMutex[outfile]
	s.mu.RUnlock()

	if exists {
		return mu
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if mu, exists = s.fileMutex[outfile]; exists {
		return mu
	}

	mu = &sync.Mutex{}
	s.fileMutex[outfile] = mu
	return mu
}

// writeMatch appends a URL to the specified output file with proper locking.
func (s *URLScanner) writeMatch(outfile, url string) error {
	mu := s.getMutex(outfile)
	mu.Lock()
	defer mu.Unlock()

	filepath := filepath.Join(s.resultsDir, outfile)
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening file %s: %w", filepath, err)
	}
	defer file.Close()

	if _, err := file.WriteString(url + "\n"); err != nil {
		return fmt.Errorf("writing to file %s: %w", filepath, err)
	}

	return nil
}

// matchAndRecord checks the response body against all patterns and records matches.
func (s *URLScanner) matchAndRecord(url, body string) []string {
	var matches []string

	for _, cfg := range s.configs {
		pattern := s.patterns[cfg.Name]
		if pattern.MatchString(body) {
			matches = append(matches, cfg.Name)

			if err := s.writeMatch(cfg.Outfile, url); err != nil && s.verbose {
				s.logError(url, err.Error())
			}
		}
	}

	return matches
}

// logError prints an error message with consistent formatting.
func (s *URLScanner) logError(url, errMsg string) {
	fmt.Printf("%s%s %s->%s [%s%s%s]%s\n",
		colorWhite, url, colorBlue, colorWhite, colorYellow, errMsg, colorWhite, colorReset)
}

// logMatch prints a match result with consistent formatting.
func (s *URLScanner) logMatch(url string, matches []string) {
	fmt.Printf("%s%s %s->%s [%s%s%s]%s\n",
		colorWhite, url, colorBlue, colorWhite, colorGreen, strings.Join(matches, ", "), colorWhite, colorReset)
}

// logNoMatch prints a no-match result with consistent formatting.
func (s *URLScanner) logNoMatch(url string) {
	fmt.Printf("%s%s %s->%s [%sNo matches%s]%s\n",
		colorWhite, url, colorBlue, colorWhite, colorRed, colorWhite, colorReset)
}

// ScanURL fetches and scans a single URL for pattern matches.
func (s *URLScanner) ScanURL(ctx context.Context, url string) {
	url = strings.TrimSpace(url)
	if url == "" {
		return
	}

	// Ensure URL has a scheme
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	// Create request with context for cancellation support
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		atomic.AddInt64(&s.stats.TotalErrors, 1)
		if s.verbose {
			s.logError(url, err.Error())
		}
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		atomic.AddInt64(&s.stats.TotalErrors, 1)
		if s.verbose {
			s.logError(url, err.Error())
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		atomic.AddInt64(&s.stats.TotalErrors, 1)
		if s.verbose {
			s.logError(url, err.Error())
		}
		return
	}

	atomic.AddInt64(&s.stats.TotalScanned, 1)

	matches := s.matchAndRecord(url, string(body))
	if len(matches) > 0 {
		atomic.AddInt64(&s.stats.TotalMatches, 1)
		s.logMatch(url, matches)
	} else {
		atomic.AddInt64(&s.stats.TotalNoMatches, 1)
		if !s.matchOnly {
			s.logNoMatch(url)
		}
	}
}

// GetStats returns a copy of the current statistics.
func (s *URLScanner) GetStats() Stats {
	return Stats{
		TotalScanned:   atomic.LoadInt64(&s.stats.TotalScanned),
		TotalMatches:   atomic.LoadInt64(&s.stats.TotalMatches),
		TotalErrors:    atomic.LoadInt64(&s.stats.TotalErrors),
		TotalNoMatches: atomic.LoadInt64(&s.stats.TotalNoMatches),
	}
}

// createHTTPClient creates a configured HTTP client with connection pooling.
func createHTTPClient(timeout, maxRedirects int) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // User may need to scan self-signed certs
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

// parseFlags parses and validates command-line arguments.
func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.FileName, "list", "", "File containing list of URLs (required)")
	flag.StringVar(&cfg.ConfigFile, "config", defaultConfigFile, "Path to config JSON file")
	flag.StringVar(&cfg.ResultsDir, "results", defaultResultsDir, "Directory for result files")
	flag.IntVar(&cfg.Threads, "threads", defaultThreads, "Number of worker threads (0 = NumCPU)")
	flag.IntVar(&cfg.Timeout, "timeout", defaultTimeout, "HTTP request timeout in seconds")
	flag.IntVar(&cfg.MaxRedirects, "max-redirects", defaultMaxRedirects, "Maximum redirects to follow")
	flag.IntVar(&cfg.BufferSize, "buffer", defaultBufferSize, "URL channel buffer size")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose error output")
	flag.BoolVar(&cfg.MatchOnly, "match", false, "Print only matching URLs")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -list <file> [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "URL Scanner - Scan URLs for regex pattern matches\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s -list urls.txt -threads 20 -timeout 15 -verbose\n", os.Args[0])
	}

	flag.Parse()

	if cfg.FileName == "" {
		fmt.Fprintln(os.Stderr, "Error: -list flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Set default threads to NumCPU if not specified
	if cfg.Threads <= 0 {
		cfg.Threads = runtime.NumCPU()
	}

	return cfg
}

// run executes the main scanning logic with graceful shutdown support.
func run(ctx context.Context, cfg *Config) error {
	// Load scan configurations
	configs, err := loadScanConfigs(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("loading scan configs: %w", err)
	}

	fmt.Printf("Loaded %d scan configurations from %s\n", len(configs), cfg.ConfigFile)

	// Create HTTP client
	client := createHTTPClient(cfg.Timeout, cfg.MaxRedirects)

	// Create scanner
	scanner, err := NewURLScanner(configs, client, cfg.Verbose, cfg.MatchOnly, cfg.ResultsDir)
	if err != nil {
		return fmt.Errorf("creating scanner: %w", err)
	}

	// Create results directory
	if err := os.MkdirAll(cfg.ResultsDir, 0755); err != nil {
		return fmt.Errorf("creating results directory: %w", err)
	}

	// Open URL file
	file, err := os.Open(cfg.FileName)
	if err != nil {
		return fmt.Errorf("opening URL file: %w", err)
	}
	defer file.Close()

	// Create URL channel and wait group
	urls := make(chan string, cfg.BufferSize)
	var wg sync.WaitGroup

	// Start worker pool
	fmt.Printf("Starting %d worker threads...\n", cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				select {
				case <-ctx.Done():
					return
				default:
					scanner.ScanURL(ctx, url)
				}
			}
		}()
	}

	// Read URLs and send to workers
	fileScanner := bufio.NewScanner(file)
	fileScanner.Buffer(make([]byte, maxURLLength), maxURLLength)

	urlCount := 0
	for fileScanner.Scan() {
		select {
		case <-ctx.Done():
			fmt.Println("\nShutdown requested, stopping URL reading...")
			goto cleanup
		default:
			urls <- fileScanner.Text()
			urlCount++
		}
	}

cleanup:
	close(urls)

	if err := fileScanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading URL file: %v\n", err)
	}

	// Wait for workers to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for completion or forced shutdown
	select {
	case <-done:
		// Normal completion
	case <-time.After(30 * time.Second):
		fmt.Println("Timeout waiting for workers to finish")
	}

	// Print statistics
	stats := scanner.GetStats()
	fmt.Printf("\n%s=== Scan Complete ===%s\n", colorGreen, colorReset)
	fmt.Printf("URLs Processed: %d\n", urlCount)
	fmt.Printf("Successfully Scanned: %d\n", stats.TotalScanned)
	fmt.Printf("Matches Found: %d\n", stats.TotalMatches)
	fmt.Printf("No Matches: %d\n", stats.TotalNoMatches)
	fmt.Printf("Errors: %d\n", stats.TotalErrors)

	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	cfg := parseFlags()

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Printf("\nReceived signal %v, initiating graceful shutdown...\n", sig)
		cancel()
	}()

	if err := run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
