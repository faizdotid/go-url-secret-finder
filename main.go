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
}

type ParserArg struct {
	FileName string
	Threads  int
	Timeout  int
}

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
	if len(matches) > 0 {
		fmt.Printf("%s -> [%s]\n", url, strings.Join(matches, " | "))
	} else {
		fmt.Printf("%s -> [No matches]\n", url)
	}
}

func ParseArgsFunc(args *ParserArg) {
	flag.StringVar(&args.FileName, "list", "", "File containing list of URLs")
	flag.IntVar(&args.Threads, "threads", 10, "Number of threads to use")
	flag.IntVar(&args.Timeout, "timeout", 10, "Timeout for HTTP requests")
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
	
	// var threads int
	// if len(os.Args) < 2 {
	// 	fmt.Println("Usage: go run main.go <file> [threads]")
	// 	os.Exit(1)
	// } else {
	// 	if _, err := os.Stat(os.Args[1]); err != nil {
	// 		fmt.Println("File not found:", err)
	// 		os.Exit(1)
	// 	}

	// }
	// if len(os.Args) == 3 {
	// 	threads, _ = strconv.Atoi(os.Args[2])
	// } else {
	// 	threads = 10
	// }

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
