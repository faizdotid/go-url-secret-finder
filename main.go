package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
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
	Configs []ScanConfig
	Client  *http.Client
	Verbose bool
}

type ParserArg struct {
	FileName string
	Threads  int
	Timeout  int
	Verbose  bool
}

type Color string

const (
	Red    Color = "\033[31m"
	Green  Color = "\033[32m"
	Yellow Color = "\033[33m"
	Blue   Color = "\033[34m"
	White  Color = "\033[37m"
	Reset  Color = "\033[0m"
)

func LoadScanConfigs() []ScanConfig {
	configRead, err := os.ReadFile("config.json")
	if err != nil {
		fmt.Println("Error reading config file:", err)
		os.Exit(1)
	}
	var config []ScanConfig
	// configRead := []byte(configJSON)
	err = json.Unmarshal(configRead, &config)
	if err != nil {
		fmt.Println("Error parsing config file:", err)
		os.Exit(1)
	}
	return config
}

func (scanner *URLScanner) MatchAndRecordURL(config ScanConfig, matches *[]string, body []byte, url string) {
	matched, err := regexp.Match(config.Regex, body)
	if err != nil {
		fmt.Println("Error matching regex:", err)
		return
	}
	if !matched {
		return
	}
	*matches = append(*matches, config.Name)
	file, err := os.OpenFile(fmt.Sprintf("results/%s", config.Outfile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(url + "\n")
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
}

func (scanner *URLScanner) ScanURLAndMatch(url string) {
	url = strings.TrimSpace(url)
	response, err := scanner.Client.Get(url)
	if err != nil {
		fmt.Println("Error fetching URL:", err)
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	var matches []string
	for _, config := range scanner.Configs {
		scanner.MatchAndRecordURL(config, &matches, body, url)
	}
	if !scanner.Verbose {
		return
	}
	if len(matches) > 0 {
		fmt.Printf("%s%s %s->%s [%s%s%s]%s\n", White, url, Blue, White, Green, strings.Join(matches, ", "), White, Reset)
	} else {
		fmt.Printf("%s%s %s->%s [%s%s%s]%s\n", White, url, Blue, White, Red, "No matches", White, Reset)
	}
}

func ParseArgsFunc(args *ParserArg) {
	flag.StringVar(&args.FileName, "list", "", "File containing list of URLs")
	flag.IntVar(&args.Threads, "threads", 10, "Number of threads to use")
	flag.IntVar(&args.Timeout, "timeout", 10, "Timeout for HTTP requests")
	flag.BoolVar(&args.Verbose, "verbose", false, "Print verbose output")
	flag.Parse()
	if args.FileName == "" {
		fmt.Printf("Usage: %s -list <file> [-threads <threads>] [-timeout <timeout>]\n", os.Args[0])
		flag.Usage()
		os.Exit(1)
	}
	if args.Threads < 1 {
		fmt.Println("Threads must be greater than 0")
		os.Exit(1)
	}
	if args.Timeout < 1 {
		fmt.Println("Timeout must be greater than 0")
		os.Exit(1)
	}
}

func main() {
	var args ParserArg
	ParseArgsFunc(&args)
	configs := LoadScanConfigs()
	scanner := URLScanner{
		Configs: configs,
		Client: &http.Client{
			Timeout: time.Duration(args.Timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		Verbose: args.Verbose,
	}
	if _, err := os.Stat("results"); os.IsNotExist(err) {
		os.Mkdir("results", 0755)
	}
	filBuffer, err := os.ReadFile(args.FileName)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}
	urls := strings.Split(string(filBuffer), "\n")
	var wg sync.WaitGroup
	threadChan := make(chan struct{}, args.Threads)
	for _, url := range urls {
		wg.Add(1)
		threadChan <- struct{}{}
		go func(url string) {
			defer wg.Done()
			scanner.ScanURLAndMatch(url)
			<-threadChan
		}(url)
	}
	wg.Wait()
}
