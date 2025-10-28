package main

import (
	"errors"
	"flag"
	"os"
	"strings"
)

// Config holds CLI configuration
type Config struct {
	SingleURL   string
	FileURLs    string
	PayloadFile string
	ParamLike   string
	Silent      bool
	Threads     int
	Timeout     int
	OutFile     string
	Encodings   []string // নতুন ফিল্ড: এনকোডিং মেকানিজম
	Spray       bool     // নতুন ফ্ল্যাগ: spray mode
}

func usage() {
	print(`Advance XSS Scanner v4.0.2
Developed by: github.com/h6nt3r

Options:
 -u string single URL to scan
 -f string file with URLs (one per line)
 -p string payload file (one per line) (required)
 -pl string keyword: only scan parameters whose value contains this keyword (silent skip otherwise)
 -t int number of worker threads (default 5)
 -T int timeout seconds per test (default 10)
 -e string encoding mechanisms (comma-separated, e.g., url,base64)
 -s silent: only print URLs; white for Not Vulnerable, red for XSS Found
 -spray bool  spray all payloads to all params of each URL and after end urls, if payloads remain, start again from first URL
 -o string output file (plain text, only XSS found URLs)
`)
}

func ParseFlags() (Config, error) {
	var cfg Config
	flag.StringVar(&cfg.SingleURL, "u", "", "single URL to scan")
	flag.StringVar(&cfg.FileURLs, "f", "", "file with URLs (one per line)")
	flag.StringVar(&cfg.PayloadFile, "p", "", "payload file (one per line) (required)")
	flag.StringVar(&cfg.ParamLike, "pl", "", "keyword: only scan parameters whose value contains this keyword (silent skip otherwise)")
	flag.BoolVar(&cfg.Silent, "s", false, "silent: only print URLs; white for Not Vulnerable, red for XSS Found")
	flag.IntVar(&cfg.Threads, "t", 5, "number of worker threads")
	flag.IntVar(&cfg.Timeout, "T", 10, "timeout seconds per test")
	flag.StringVar(&cfg.OutFile, "o", "", "output file (plain text, only XSS found URLs)")
	encoding := flag.String("e", "", "encoding mechanisms (comma-separated, e.g., url,base64)")
	flag.BoolVar(&cfg.Spray, "spray", false, "spray all payloads to all params of each URL and after end urls, if payloads remain, start again from first URL")
	help := flag.Bool("h", false, "help")
	flag.Parse()

	if *help {
		usage()
		return cfg, errors.New("help")
	}

	// payload file required
	if cfg.PayloadFile == "" {
		return cfg, errors.New("payload file required (-p)")
	}
	if *encoding != "" {
		cfg.Encodings = strings.Split(*encoding, ",")
	}
	silentOnly = cfg.Silent

	// Ensure one of: -u, -f, or piped stdin is provided.
	// Detect piped stdin by checking if stdin is NOT a terminal (i.e., not a char device).
	piped := false
	if fi, err := os.Stdin.Stat(); err == nil {
		if (fi.Mode() & os.ModeCharDevice) == 0 {
			piped = true
		}
	}

	if cfg.SingleURL == "" && cfg.FileURLs == "" && !piped {
		usage()
		return cfg, errors.New("one of -u (single URL), -f (URL file) or piped stdin is required")
	}

	return cfg, nil
}
