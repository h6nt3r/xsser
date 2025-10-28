package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
)

func main() {
	scanStart = time.Now()

	// parse flags
	cfg, err := ParseFlags()
	if err != nil {
		if err.Error() == "help" {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// load URLs (from -u, -f or stdin)
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
		stdinLines, err := ReadStdinLines()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		if stdinLines != nil && len(stdinLines) > 0 {
			urls = append(urls, stdinLines...)
		}
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "No URLs provided. Use -u, -f or pipe URLs via stdin.")
		os.Exit(1)
	}

	// load payloads
	payloads, err := ReadLines(cfg.PayloadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading payload file: %v\n", err)
		os.Exit(1)
	}
	if len(payloads) == 0 {
		fmt.Fprintln(os.Stderr, "No payloads found in payload file.")
		os.Exit(1)
	}

	// context that we can cancel on interrupt
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// create chrome allocator
	allocCtx, allocCancel, err := CreateSharedAllocator(ctx, ChromePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating allocator: %v\n", err)
		os.Exit(1)
	}
	// keep allocCancel so we can call it on interrupt
	defer allocCancel()

	// channels with moderate buffer to avoid huge memory use
	jobs := make(chan Job, 200)
	results := make(chan string, 200)

	// start workers
	wg := StartWorkers(ctx, allocCtx, cfg.Threads, jobs, results, cfg.Timeout)

	// start results writer
	done := StartResultsWriter(cfg.OutFile, results, cfg.Silent)

	// Stream jobs in background (will close jobs when done)
	go func() {
		_ = StreamJobs(ctx, urls, payloads, cfg.ParamLike, cfg.Encodings, cfg.Spray, jobs)
		// ensure jobs channel closed when streaming finishes or context cancelled
		close(jobs)
	}()

	// handle interrupt
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// wait for workers to finish
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	// main select: wait for normal completion or interrupt
	select {
	case <-waitCh:
		// normal completion
	case <-interrupt:
		// print ^C line like you asked, then message
		fmt.Println("^C")
		fmt.Fprintln(os.Stderr, "Interrupt received — stopping gracefully...")

		// set stopping flag so workers stop printing/sending results
		atomic.StoreInt32(&stopping, 1)

		// cancel streaming and contexts so StreamJobs and workers wake up
		cancel()

		// try to cancel chrome allocator to hasten shutdown
		allocCancel()

		// wait for workers to actually finish
		<-waitCh
	}

	// all workers done — close results and wait writer
	close(results)
	<-done

	// print summary (always show)
	totalDur := time.Since(scanStart)
	totalSeconds := int(totalDur.Seconds())
	minutes := totalSeconds / 60
	seconds := totalSeconds % 60

	fmt.Printf("Total Time Taken: %d Minute %d Second\n", minutes, seconds)
	fmt.Printf("Total XSS Found: %d\n", atomicLoadInt64(&totalXSSFound))
	fmt.Printf("Total Timeouts: %d\n", atomicLoadInt64(&totalTimeout))
	fmt.Printf("Total Errors: %d\n", atomicLoadInt64(&totalError))
}
