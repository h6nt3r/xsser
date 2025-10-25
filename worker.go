package main

import (
    "context"
    "errors"
    "fmt"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/chromedp/cdproto/page"
    "github.com/chromedp/chromedp"
)

func StartWorkers(parentCtx context.Context, allocCtx context.Context, count int, jobs <-chan Job, results chan<- string, timeout int) *sync.WaitGroup {
    var wg sync.WaitGroup
    if count <= 0 {
        count = 5
    }
    for i := 0; i < count; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            worker(id, jobs, results, timeout, allocCtx)
        }(i + 1)
    }
    return &wg
}

func worker(id int, jobs <-chan Job, results chan<- string, timeoutSec int, allocCtx context.Context) {
    ctx, cancel := chromedp.NewContext(allocCtx)
    defer cancel()

    // warm-up noop
    _ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error { return nil }))

    for job := range jobs {
        jobCtx, jobCancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
        // ensure cancel called at end of iteration
        func() {
            defer jobCancel()

            found := false
            foundURL := ""

            // dialog listening
            listenCtx, listenCancel := context.WithCancel(jobCtx)
            defer listenCancel()
            dialogCh := make(chan *page.EventJavascriptDialogOpening, 1)
            chromedp.ListenTarget(listenCtx, func(ev interface{}) {
                switch e := ev.(type) {
                case *page.EventJavascriptDialogOpening:
                    select {
                    case dialogCh <- e:
                    default:
                    }
                default:
                    _ = e
                }
            })

            mutated := buildMutatedURLWithReserve(job.OriginalURL, job.ParamsOrder, job.TargetParam, job.Payload, job.ReserveValue, job.OtherOrigValues)

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
                    _ = chromedp.Run(jobCtx, chromedp.ActionFunc(func(ctx context.Context) error { return page.HandleJavaScriptDialog(true).Do(ctx) }))
                } else {
                    _ = chromedp.Run(jobCtx, chromedp.ActionFunc(func(ctx context.Context) error { return page.HandleJavaScriptDialog(true).Do(ctx) }))
                }
            default:
            }

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
                    fmt.Printf("[%d/%d] Not Vulnerable (%s%s%s): %s\n\n", job.IdxURL, job.TotalURLs, skyblue, job.TargetParam, reset, mutated)
                }
                return
            }

            if found {
                atomic.AddInt64(&totalXSSFound, 1)
                if silentOnly {
                    fmt.Printf("%s%s%s\n", red, foundURL, reset)
                } else {
                    fmt.Printf("[%d/%d] XSS Found (%s%s%s): %s%s%s\n\n", job.IdxURL, job.TotalURLs, skyblue, job.TargetParam, reset, red, foundURL, reset)
                }
                results <- foundURL
            } else {
                if silentOnly {
                    fmt.Printf("%s%s%s\n", white, mutated, reset)
                } else {
                    fmt.Printf("[%d/%d] Not Vulnerable (%s%s%s): %s\n\n", job.IdxURL, job.TotalURLs, skyblue, job.TargetParam, reset, mutated)
                }
            }
        }()
    }
}