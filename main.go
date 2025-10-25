package main

import (
    "context"
    "fmt"
    "os"
    "time"
)

func main() {
    scanStart = time.Now()

    // ফ্ল্যাগ পার্স করা
    cfg, err := ParseFlags()
    if err != nil {
        if err.Error() == "help" {
            os.Exit(0)
        }
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }

    // URL এবং পেলোড পড়া
    urls := []string{}
    if cfg.SingleURL != "" {
        urls = append(urls, cfg.SingleURL)
    }
    if cfg.FileURLs != "" {
        fURLs, err := ReadLines(cfg.FileURLs)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error reading URL file: %v\n", err)
            os.Exit(1)
        }
        urls = append(urls, fURLs...)
    }
    if len(urls) == 0 {
        urls, err = ReadStdinLines()
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
            os.Exit(1)
        }
    }

    payloads, err := ReadLines(cfg.PayloadFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading payload file: %v\n", err)
        os.Exit(1)
    }

    // জব তৈরি
    jobsList, err := BuildJobs(urls, payloads, cfg.ParamLike, cfg.Encodings)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error building jobs: %v\n", err)
        os.Exit(1)
    }

    // চ্যানেল এবং কনটেক্সট
    jobs := make(chan Job, len(jobsList))
    results := make(chan string, len(jobsList))
    ctx := context.Background()

    // Chrome অ্যালোকেটর
    allocCtx, allocCancel, err := CreateSharedAllocator(ctx, ChromePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error creating allocator: %v\n", err)
        os.Exit(1)
    }
    defer allocCancel()

    // ওয়ার্কার শুরু
    wg := StartWorkers(ctx, allocCtx, cfg.Threads, jobs, results, cfg.Timeout)

    // জব পাঠানো
    go func() {
        for _, j := range jobsList {
            jobs <- j
        }
        close(jobs)
    }()

    // ফলাফল লেখা
    done := StartResultsWriter(cfg.OutFile, results, cfg.Silent)

    // ওয়ার্কার এবং ফলাফলের জন্য অপেক্ষা
    wg.Wait()
    close(results)
    <-done

    // স্ক্যানের সারাংশ প্রিন্ট
    if !cfg.Silent {
        fmt.Printf("Scan completed in %v\n", time.Since(scanStart))
        fmt.Printf("Total XSS Found: %d\n", atomicLoadInt64(&totalXSSFound))
        fmt.Printf("Total Timeouts: %d\n", atomicLoadInt64(&totalTimeout))
        fmt.Printf("Total Errors: %d\n", atomicLoadInt64(&totalError))
    }
}