package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"errors"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/page"
)

var (
	chromePath = "/usr/bin/google-chrome"
)

const (
	red     = "\033[31m"
	skyblue = "\033[36m"
	white   = "\033[37m"
	reset   = "\033[0m"
)

// counters for summary
var totalXSSFound int64
var totalTimeout int64
var totalError int64
var scanStart time.Time

// flags
var silentOnly bool

type Job struct {
	OriginalURL     string
	TargetParam     string
	Payload         string
	ReserveValue    string
	TargetOrigValue string
	ParamsOrder     []string
	OtherOrigValues map[string]string
	IdxURL          int
	TotalURLs       int
	IdxParam        int
	TotalParam      int
	IdxPayload      int
	TotalPay        int
}

func usage() {
	fmt.Println(`Advance XSS Scanner
Developed by: github.com/h6nt3r

Flags:
  -u string   single URL to scan
  -f string   file with URLs (one per line)
  -p string   payload file (one per line) (required)
  -pl string  keyword: only scan parameters whose value contains this keyword (silent skip otherwise)
  -s          silent: only print URLs
  -t int      number of worker threads (default 5)
  -T int      timeout seconds per test (default 10)
  -o string   output file (plain text, only XSS found URLs)
`)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var lines []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func createSharedAllocator(ctx context.Context) (context.Context, context.CancelFunc, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-popup-blocking", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	return allocCtx, cancel, nil
}

// buildMutatedURLWithReserve builds a mutated URL where targetParam has payload (verbatim)
func buildMutatedURLWithReserve(rawURL string, paramsOrder []string, targetParam, payload, reserveValue string, otherOrig map[string]string) string {
	prefix := rawURL
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		prefix = rawURL[:idx]
	}

	var parts []string
	for _, k := range paramsOrder {
		v := reserveValue
		if k == targetParam {
			v = payload
		} else if otherOrig != nil {
			if ov, ok := otherOrig[k]; ok {
				v = ov
			}
		}
		parts = append(parts, k+"="+v)
	}

	if strings.Contains(rawURL, "?") {
		return prefix + "?" + strings.Join(parts, "&")
	}
	return prefix + "?" + strings.Join(parts, "&")
}

func worker(id int, jobs <-chan Job, results chan<- string, wg *sync.WaitGroup, timeoutSec int, allocCtx context.Context) {
	defer wg.Done()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// warm-up noop
	_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error { return nil }))

	for job := range jobs {
		jobCtx, jobCancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)

		found := false
		foundURL := ""

		// dialog listening
		listenCtx, listenCancel := context.WithCancel(jobCtx)
		dialogCh := make(chan *page.EventJavascriptDialogOpening, 1)
		chromedp.ListenTarget(listenCtx, func(ev interface{}) {
			switch e := ev.(type) {
			case *page.EventJavascriptDialogOpening:
				select {
				case dialogCh <- e:
				default:
				}
			}
		})

		mutated := buildMutatedURLWithReserve(job.OriginalURL, job.ParamsOrder, job.TargetParam, job.Payload, job.ReserveValue, job.OtherOrigValues)

		// navigate + wait (no Sleep)
		err := chromedp.Run(jobCtx,
			chromedp.Navigate(mutated),
			chromedp.WaitReady("body", chromedp.ByQuery),
			chromedp.WaitVisible("body", chromedp.ByQuery),
		)

		// check dialogs
		select {
		case ev := <-dialogCh:
			typ := strings.ToLower(fmt.Sprint(ev.Type))
			if strings.Contains(typ, "alert") || strings.Contains(typ, "prompt") || strings.Contains(typ, "confirm") {
				found = true
				foundURL = mutated
				_ = chromedp.Run(jobCtx, chromedp.ActionFunc(func(ctx context.Context) error {
					return page.HandleJavaScriptDialog(true).Do(ctx)
				}))
			} else {
				_ = chromedp.Run(jobCtx, chromedp.ActionFunc(func(ctx context.Context) error {
					return page.HandleJavaScriptDialog(true).Do(ctx)
				}))
			}
		default:
		}

		listenCancel()
		jobCancel()

		// handle results & print
		if err != nil && !found {
			if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
				atomic.AddInt64(&totalTimeout, 1)
			} else {
				atomic.AddInt64(&totalError, 1)
			}
			if silentOnly {
				fmt.Printf("%s%s%s\n", white, mutated, reset)
			} else {
				fmt.Printf("[%d/%d] Not Vulnerable (%s%s%s): %s\n\n",
					job.IdxURL, job.TotalURLs, skyblue, job.TargetParam, reset, mutated)
			}
			continue
		}

		if found {
			atomic.AddInt64(&totalXSSFound, 1)
			if silentOnly {
				fmt.Printf("%s%s%s\n", red, foundURL, reset)
			} else {
				fmt.Printf("[%d/%d] XSS Found (%s%s%s): %s%s%s\n\n",
					job.IdxURL, job.TotalURLs, skyblue, job.TargetParam, reset, red, foundURL, reset)
			}
			results <- foundURL
		} else {
			if silentOnly {
				fmt.Printf("%s%s%s\n", white, mutated, reset)
			} else {
				fmt.Printf("[%d/%d] Not Vulnerable (%s%s%s): %s\n\n",
					job.IdxURL, job.TotalURLs, skyblue, job.TargetParam, reset, mutated)
			}
		}
	}
}

func main() {
	u := flag.String("u", "", "single URL to scan")
	f := flag.String("f", "", "file with URLs (one per line)")
	p := flag.String("p", "", "payload file (one per line) (required)")
	pl := flag.String("pl", "", "keyword: only scan parameters whose value contains this keyword (silent skip otherwise)")
	sFlag := flag.Bool("s", false, "silent: only print URLs; white for Not Vulnerable, red for XSS Found")
	threads := flag.Int("t", 5, "number of worker threads")
	timeoutSec := flag.Int("T", 10, "timeout seconds per test")
	out := flag.String("o", "", "output file (plain text, only XSS found URLs)")
	help := flag.Bool("h", false, "help")
	flag.Usage = usage
	flag.Parse()

	silentOnly = *sFlag

	if *help {
		usage()
		return
	}

	if *p == "" {
		fmt.Println("payload file required (-p).")
		os.Exit(1)
	}

	var urls []string
	if *u != "" {
		urls = append(urls, *u)
	}
	if *f != "" {
		lines, err := readLines(*f)
		if err != nil {
			fmt.Printf("failed to read url file: %v\n", err)
			os.Exit(1)
		}
		urls = append(urls, lines...)
	}

	if len(urls) == 0 {
		if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				urls = append(urls, line)
			}
			if err := sc.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
				os.Exit(1)
			}
		}
		if len(urls) == 0 {
			fmt.Println("no URLs provided. use -u, -f or pipe URLs to stdin")
			os.Exit(1)
		}
	}

	if *pl != "" {
		var filtered []string
		for _, rawURL := range urls {
			parsed, err := url.Parse(rawURL)
			if err != nil {
				if strings.Contains(rawURL, *pl) {
					filtered = append(filtered, rawURL)
				}
				continue
			}
			found := false
			values, _ := url.ParseQuery(parsed.RawQuery)
			for _, vlist := range values {
				for _, v := range vlist {
					if strings.Contains(v, *pl) {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				filtered = append(filtered, rawURL)
			}
		}
		urls = filtered
	}

	if len(urls) == 0 {
		os.Exit(0)
	}

	payloads, err := readLines(*p)
	if err != nil {
		fmt.Printf("failed to read payload file: %v\n", err)
		os.Exit(1)
	}
	if len(payloads) == 0 {
		fmt.Println("payload file empty")
		os.Exit(1)
	}

	var jobsList []Job
	for ui, raw := range urls {
		parsed, err := url.Parse(raw)
		params := []string{}
		origValues := map[string]string{}

		if err == nil && parsed.RawQuery != "" {
			parts := strings.Split(parsed.RawQuery, "&")
			for _, part := range parts {
				if part == "" {
					continue
				}
				if idx := strings.Index(part, "="); idx >= 0 {
					k := part[:idx]
					v := ""
					if idx+1 <= len(part)-1 {
						v = part[idx+1:]
					}
					params = append(params, k)
					origValues[k] = v
				}
			}
		} else if strings.Contains(raw, "=") {
			var tail string
			if idx := strings.Index(raw, "?"); idx >= 0 {
				tail = raw[idx+1:]
			} else {
				tail = raw
			}
			for _, part := range strings.Split(tail, "&") {
				if part == "" {
					continue
				}
				if idx := strings.Index(part, "="); idx >= 0 {
					k := part[:idx]
					v := ""
					if idx+1 <= len(part)-1 {
						v = part[idx+1:]
					}
					params = append(params, k)
					origValues[k] = v
				}
			}
		}

		if len(params) == 0 {
			continue
		}

		reserveValue := ""
		if v, ok := origValues[params[0]]; ok {
			reserveValue = v
		}
		prevReserve := reserveValue

		for pi, param := range params {
			if *pl != "" {
				ov := ""
				if v, ok := origValues[param]; ok {
					ov = v
				}
				if !strings.Contains(ov, *pl) {
					continue
				}
			}
			origVal := ""
			if v, ok := origValues[param]; ok {
				origVal = v
			}
			currReserve := prevReserve
			for xi, payload := range payloads {
				otherCopy := make(map[string]string, len(origValues))
				for kk, vv := range origValues {
					otherCopy[kk] = vv
				}
				jobsList = append(jobsList, Job{
					OriginalURL:     raw,
					TargetParam:     param,
					Payload:         payload,
					ReserveValue:    currReserve,
					TargetOrigValue: origVal,
					ParamsOrder:     params,
					OtherOrigValues: otherCopy,
					IdxURL:          ui + 1,
					TotalURLs:       len(urls),
					IdxParam:        pi + 1,
					TotalParam:      len(params),
					IdxPayload:      xi + 1,
					TotalPay:        len(payloads),
				})
			}
			prevReserve = origVal
		}
	}

	if len(jobsList) == 0 {
		fmt.Println("no injectable parameters found in provided URLs")
		os.Exit(0)
	}

	jobs := make(chan Job)
	results := make(chan string)
	var wg sync.WaitGroup

	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()

	// Shared Chrome allocator
	allocCtx, allocCancel, err := createSharedAllocator(parentCtx)
	if err != nil {
		fmt.Printf("failed to create Chrome allocator: %v\n", err)
		os.Exit(1)
	}
	defer allocCancel()

	workerCount := *threads
	if workerCount <= 0 {
		workerCount = 5
	}

	scanStart = time.Now()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(i+1, jobs, results, &wg, *timeoutSec, allocCtx)
	}

	var outFile *os.File
	var outMu sync.Mutex
	if *out != "" {
		dir := filepath.Dir(*out)
		if dir != "." {
			_ = os.MkdirAll(dir, 0o755)
		}
		fh, err := os.Create(*out)
		if err != nil {
			fmt.Printf("failed to create output file: %v\n", err)
			os.Exit(1)
		}
		outFile = fh
		defer outFile.Close()
	}

	var resWg sync.WaitGroup
	resWg.Add(1)
	go func() {
		defer resWg.Done()
		seen := make(map[string]bool)
		for r := range results {
			if seen[r] {
				continue
			}
			seen[r] = true
			if outFile != nil {
				outMu.Lock()
				_, _ = outFile.WriteString(r + "\n")
				outMu.Unlock()
			}
		}
	}()

	go func() {
		for _, j := range jobsList {
			jobs <- j
		}
		close(jobs)
	}()

	wg.Wait()
	close(results)
	resWg.Wait()

	elapsed := time.Since(scanStart)
	minutes := int(elapsed.Minutes())
	seconds := int(elapsed.Seconds()) - minutes*60

	found := atomic.LoadInt64(&totalXSSFound)
	touts := atomic.LoadInt64(&totalTimeout)
	errs := atomic.LoadInt64(&totalError)

	if !silentOnly {
		fmt.Printf("\nTotal XSS Found: %d\n", found)
		fmt.Printf("Total Time Taken: %d Minute %d Second\n", minutes, seconds)
		fmt.Printf("Total Timeout: %d\n", touts)
		fmt.Printf("Total Error: %d\n", errs)
	}
}
