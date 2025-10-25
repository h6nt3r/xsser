package main

import (
    "errors"
    "flag"
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
}

func usage() {
    print(`Advance XSS Scanner v4.0.1
Developed by: github.com/h6nt3r

Flags:
 -u string single URL to scan
 -f string file with URLs (one per line)
 -p string payload file (one per line) (required)
 -pl string keyword: only scan parameters(FUZZ) whose value contains this keyword (silent skip otherwise)
 -t int number of worker threads (default 5)
 -T int timeout seconds per test (default 10)
 -e string encoding mechanisms (comma-separated, e.g., url,base64)
 -s silent: only print URLs; white for Not Vulnerable, red for XSS Found
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
    help := flag.Bool("h", false, "help")
    flag.Parse()
    if *help {
        usage()
        return cfg, errors.New("help")
    }
    if cfg.PayloadFile == "" {
        return cfg, errors.New("payload file required (-p)")
    }
    if *encoding != "" {
        cfg.Encodings = strings.Split(*encoding, ",")
    }
    silentOnly = cfg.Silent
    return cfg, nil
}