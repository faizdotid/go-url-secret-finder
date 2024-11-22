package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type ScanConfig struct {
	Name    string `json:"name"`
	Regex   string `json:"regex"`
	Outfile string `json:"outfile"`
}

type URLScanner struct {
	Configs  []ScanConfig
	Client   *http.Client
	Verbose  bool
	Match    bool
	patterns map[string]*regexp.Regexp
}

type ParserArg struct {
	FileName     string
	Threads      int
	Timeout      int
	Verbose      bool
	Match        bool
	MaxRedirects int
	BufferSize   int
}

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	White  = "\033[37m"
	Reset  = "\033[0m"
)

func LoadScanConfigs() ([]ScanConfig, error) {
	configRead, err := os.ReadFile("config.json")
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var config []ScanConfig
	if err := json.Unmarshal(configRead, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return config, nil
}

func (s *URLScanner) initPatterns() error {
	s.patterns = make(map[string]*regexp.Regexp, len(s.Configs))
	for _, cfg := range s.Configs {
		pattern, err := regexp.Compile(cfg.Regex)
		if err != nil {
			return fmt.Errorf("compiling regex %s: %w", cfg.Name, err)
		}
		s.patterns[cfg.Name] = pattern
	}
	return nil
}

func (s *URLScanner) writeMatch(outfile, url string) error {
	file, err := os.OpenFile(
		fmt.Sprintf("results/%s", outfile),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(url + "\n"); err != nil {
		return err
	}
	return nil
}

func (s *URLScanner) MatchAndRecordURL(url string, body string) []string {
	var matches []string
	for _, config := range s.Configs {
		if s.patterns[config.Name].MatchString(body) {
			matches = append(matches, config.Name)
			if err := s.writeMatch(config.Outfile, url); err != nil && s.Verbose {
				fmt.Printf("%s%s %s->%s [%s%s%s]%s\n", White, url, Blue, White, Yellow, err.Error(), White, Reset)
			}
		}
	}
	return matches
}

func (s *URLScanner) ScanURLAndMatch(url string) {
	url = strings.TrimSpace(url)
	if url == "" {
		return
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	response, err := s.Client.Get(url)
	if err != nil {
		if s.Verbose {
			fmt.Printf("%s%s %s->%s [%s%s%s]%s\n", White, url, Blue, White, Yellow, err.Error(), White, Reset)
		}
		return
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		if s.Verbose {
			fmt.Printf("%s%s %s->%s [%s%s%s]%s\n", White, url, Blue, White, Yellow, err.Error(), White, Reset)
		}
		return
	}

	matches := s.MatchAndRecordURL(url, string(body))
	if len(matches) > 0 {
		fmt.Printf("%s%s %s->%s [%s%s%s]%s\n", White, url, Blue, White, Green, strings.Join(matches, ", "), White, Reset)
	} else if !s.Match {
		fmt.Printf("%s%s %s->%s [%s%s%s]%s\n", White, url, Blue, White, Red, "No matches", White, Reset)
	}
}

func ParseArgsFunc() *ParserArg {
	args := &ParserArg{}
	flag.StringVar(&args.FileName, "list", "", "File containing list of URLs")
	flag.IntVar(&args.Threads, "threads", runtime.NumCPU(), "Number of threads to use")
	flag.IntVar(&args.Timeout, "timeout", 10, "Timeout for HTTP requests")
	flag.IntVar(&args.MaxRedirects, "max-redirects", 10, "Maximum number of redirects to follow")
	flag.IntVar(&args.BufferSize, "buffer", 1000, "Size of the URL processing buffer")
	flag.BoolVar(&args.Verbose, "verbose", false, "Print verbose output")
	flag.BoolVar(&args.Match, "match", false, "Print only match url")
	flag.Parse()

	if args.FileName == "" {
		fmt.Printf("Usage: %s -list <file> [-threads <threads>] [-timeout <timeout>] [-verbose] [-match]\n", os.Args[0])
		flag.Usage()
		os.Exit(1)
	}

	return args
}

func createHTTPClient(timeout int, maxRedirects int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	args := ParseArgsFunc()

	configs, err := LoadScanConfigs()
	if err != nil {
		fmt.Printf("Error loading configs: %v\n", err)
		os.Exit(1)
	}

	scanner := &URLScanner{
		Configs: configs,
		Client:  createHTTPClient(args.Timeout, args.MaxRedirects),
		Verbose: args.Verbose,
		Match:   args.Match,
	}

	if err := scanner.initPatterns(); err != nil {
		fmt.Printf("Error initializing patterns: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll("results", 0755); err != nil {
		fmt.Printf("Error creating results directory: %v\n", err)
		os.Exit(1)
	}

	file, err := os.Open(args.FileName)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	urls := make(chan string, args.BufferSize)
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < args.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				scanner.ScanURLAndMatch(url)
			}
		}()
	}

	// Read URLs and send to workers
	scannerbuf := bufio.NewScanner(file)
	for scannerbuf.Scan() {
		urls <- scannerbuf.Text()
	}
	close(urls)

	if err := scannerbuf.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}

	wg.Wait()
}
