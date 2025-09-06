package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		fmt.Printf("[DEBUG] %s: Failed to create HTTPS request: %v\n", domain, err)
		continue
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0)")
	httpResp, err = client.Do(req)"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

type Fingerprint struct {
	Name        string   `json:"name"`
	CNAME       []string `json:"cname"`
	Fingerprints []string `json:"fingerprints"`
	Note        string   `json:"note,omitempty"`
}

type Result struct {
	Domain     string
	CNAME      string
	Service    string
	Vuln       bool
	Error      string
	StatusCode int
	FinalURL   string
}

func loadFingerprints(file string) ([]Fingerprint, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var fps []Fingerprint
	err = json.Unmarshal(data, &fps)
	if err != nil {
		return nil, err
	}
	return fps, nil
}

func loadDomains(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

func isWildcard(domain string) bool {
	randomSub := "randomsub." + domain
	ips1, err1 := net.LookupHost(domain)
	if err1 != nil {
		return false
	}
	ips2, err2 := net.LookupHost(randomSub)
	if err2 != nil {
		return false
	}
	if len(ips1) == 0 || len(ips2) == 0 {
		return false
	}
	return ips1[0] == ips2[0]
}

func checkDomain(domain string, fingerprints []Fingerprint, client *http.Client, retry int) Result {
	fmt.Printf("[DEBUG] Processing domain: %s\n", domain)
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return Result{Domain: domain, Error: "DNS CNAME: " + err.Error()}
	}

	cname = strings.TrimSuffix(cname, ".")

	if isWildcard(domain) {
		return Result{Domain: domain, CNAME: cname, Service: "", Vuln: false, Error: "Wildcard domain", StatusCode: 0, FinalURL: ""}
	}

	_, err = net.LookupHost(domain)
	if err != nil {
		return Result{Domain: domain, CNAME: cname, Error: "DNS A: " + err.Error()}
	}

	// Fetch HTTP content with retry
	var httpResp *http.Response
	for i := 0; i < retry; i++ {
		req, err := http.NewRequest("GET", "https://"+domain, nil)
		if err != nil {
			fmt.Printf("[DEBUG] %s: Failed to create HTTPS request: %v\n", domain, err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0)")
		httpResp, err = client.Do(req)
		if err == nil {
			fmt.Printf("[DEBUG] %s: HTTPS success\n", domain)
			break
		}
		fmt.Printf("[DEBUG] %s: HTTPS failed (attempt %d): %v\n", domain, i+1, err)
	}
	if httpResp == nil || httpResp.StatusCode == 0 {
		// Try HTTP
		req, err := http.NewRequest("GET", "http://"+domain, nil)
		if err != nil {
			fmt.Printf("[DEBUG] %s: Failed to create HTTP request: %v\n", domain, err)
			return Result{Domain: domain, CNAME: cname, Service: "", Vuln: false, StatusCode: 0, FinalURL: "", Error: "HTTP Request: " + err.Error()}
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0)")
		httpResp, err = client.Do(req)
		if err != nil {
			fmt.Printf("[DEBUG] %s: HTTP failed: %v\n", domain, err)
			return Result{Domain: domain, CNAME: cname, Service: "", Vuln: false, StatusCode: 0, FinalURL: "", Error: "HTTP: " + err.Error()}
		}
		fmt.Printf("[DEBUG] %s: HTTP success\n", domain)
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return Result{Domain: domain, CNAME: cname, Service: "", Vuln: false, StatusCode: httpResp.StatusCode, FinalURL: httpResp.Request.URL.String(), Error: "HTTP Body: " + err.Error()}
	}
	content := string(body)

	// Set status and final URL
	statusCode := httpResp.StatusCode
	finalURL := httpResp.Request.URL.String()
	fmt.Printf("[DEBUG] %s: Status %d, Final URL: %s\n", domain, statusCode, finalURL)

	for _, fp := range fingerprints {
		for _, cn := range fp.CNAME {
			if strings.Contains(cname, cn) {
				fmt.Printf("[DEBUG] %s: CNAME match for %s\n", domain, fp.Name)
				for _, fstr := range fp.Fingerprints {
					if strings.Contains(strings.ToLower(content), strings.ToLower(fstr)) {
						fmt.Printf("[DEBUG] %s: Fingerprint match: %s\n", domain, fstr)
						return Result{Domain: domain, CNAME: cname, Service: fp.Name, Vuln: true, StatusCode: statusCode, FinalURL: finalURL}
					}
				}
			}
		}
	}

	return Result{Domain: domain, CNAME: cname, Service: "", Vuln: false, StatusCode: statusCode, FinalURL: finalURL}
}

func main() {
	fmt.Println("                    _             ")
	fmt.Println("   ___   __ __ __  (_)    __ __   ")
	fmt.Println("  (_-<   \\ V  V /  | |    \\ V /  ")
	fmt.Println("  /__/_   \\_/\\_/  _|_|_   _\\_/_  ")
	fmt.Println("_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"| ")
	fmt.Println("`-0-0-'`-0-0-'`-0-0-'`-0-0-'")
	fmt.Println("@swiv private Subs takeover...")

	domainFile := flag.String("l", "", "File containing list of domains")
	fingerprintFile := flag.String("f", "fingerprints.json", "Fingerprints JSON file")
	concurrency := flag.Int("j", 20, "Number of concurrent checks")
	output := flag.String("o", "", "Output file (optional)")
	onlyVuln := flag.Bool("vuln", false, "Show only vulnerable domains")
	timeout := flag.Duration("timeout", 10*time.Second, "HTTP timeout duration")
	retry := flag.Int("retry", 3, "Number of retries for failed requests")
	flag.Parse()

	if *domainFile == "" {
		flag.Usage()
		return
	}

	var outFile *os.File
	if *output != "" {
		var err error
		outFile, err = os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Println("Error opening output file:", err)
			return
		}
		defer outFile.Close()
	}

	fps, err := loadFingerprints(*fingerprintFile)
	if err != nil {
		fmt.Println("Error loading fingerprints:", err)
		return
	}

	domains, err := loadDomains(*domainFile)
	if err != nil {
		fmt.Println("Error loading domains:", err)
		return
	}

	fmt.Printf("[*] Loaded %d fingerprints\n", len(fps))
	fmt.Printf("[*] Loaded %d domains\n\n", len(domains))

	client := &http.Client{
		Timeout: *timeout,
	}

	resultsChan := make(chan Result)
	var wg sync.WaitGroup
	sem := make(chan struct{}, *concurrency)

	var processed int64
	var vulnCount int64
	var errorCount int64

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			sem <- struct{}{}
			res := checkDomain(domain, fps, client, *retry)
			atomic.AddInt64(&processed, 1)
			<-sem
			resultsChan <- res
		}(d)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for res := range resultsChan {
		if res.Vuln {
			atomic.AddInt64(&vulnCount, 1)
		}
		if res.Error != "" {
			atomic.AddInt64(&errorCount, 1)
		}
		// Progress indicator
		current := atomic.LoadInt64(&processed)
		if current%10 == 0 || current == int64(len(domains)) {
			fmt.Printf("[*] Processed: %d/%d\n", current, len(domains))
		}
		if *onlyVuln && !res.Vuln {
			continue
		}
		var msg string
		if res.Error != "" {
			msg = fmt.Sprintf("[-] %s -> %s\n", res.Domain, res.Error)
			color.Red(msg[:len(msg)-1])
		} else if res.Vuln {
			msg = fmt.Sprintf("[+] %s -> Potential takeover on %s (CNAME: %s)\n", res.Domain, res.Service, res.CNAME)
			green := color.New(color.FgGreen)
			cyan := color.New(color.FgCyan)
			red := color.New(color.FgRed)
			yellow := color.New(color.FgYellow)
			coloredLine := green.Sprint("[+] ") + cyan.Sprint(res.Domain) + " -> Potential takeover on " + red.Sprint(res.Service) + " (CNAME: " + yellow.Sprint(res.CNAME) + ")"
			fmt.Println(coloredLine)
		} else {
			msg = fmt.Sprintf("[-] %s -> no fingerprint match (CNAME: %s)\n", res.Domain, res.CNAME)
			color.Yellow(msg[:len(msg)-1])
		}
		if outFile != nil {
			outFile.WriteString(msg)
		}
	}

	// Print statistics
	total := atomic.LoadInt64(&processed)
	vuln := atomic.LoadInt64(&vulnCount)
	errs := atomic.LoadInt64(&errorCount)
	fmt.Printf("[*] Scan completed\n")
	fmt.Printf("[*] Total domains: %d\n", total)
	fmt.Printf("[*] Vulnerable: %d\n", vuln)
	fmt.Printf("[*] Errors: %d\n", errs)
}
