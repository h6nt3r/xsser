package main

import (
    "os"
    "sync"
)

// StartResultsWriter writes unique results to file (if provided) and returns a stop channel that
// will be closed when writer is done.
func StartResultsWriter(outPath string, results <-chan string, silent bool) chan struct{} {
    done := make(chan struct{})
    go func() {
        var fh *os.File
        var mu sync.Mutex
        seen := make(map[string]bool)
        if outPath != "" {
            f, err := os.Create(outPath)
            if err == nil {
                fh = f
                defer fh.Close()
            }
        }
        for r := range results {
            if seen[r] {
                continue
            }
            seen[r] = true
            if fh != nil {
                mu.Lock()
                _, _ = fh.WriteString(r + "\n")
                mu.Unlock()
            }
        }
        close(done)
    }()
    return done
}