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

// ... অন্যান্য ইম্পোর্ট ও ফাংশন উপরে থাকবে ...

func worker(id int, jobs <-chan Job, results chan<- string, timeoutSec int, allocCtx context.Context) {
    ctx, cancel := chromedp.NewContext(allocCtx)
    defer cancel()

    // warm-up noop
    _ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error { return nil }))

    for job := range jobs {
        // যদি already stopping হয়, দ্রুত বের হয়ে যাও
        if atomic.LoadInt32(&stopping) == 1 {
            return
        }

        jobCtx, jobCancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
        // ensure cancel called at end of iteration
        func() {
            defer jobCancel()

            // 또 একবার চেক করে নাও প্রথমেই
            if atomic.LoadInt32(&stopping) == 1 {
                return
            }

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

            // build mutated url (spray-aware)
            mutated := buildMutatedURLWithReserve(job.OriginalURL, job.ParamsOrder, job.TargetParam, job.Payload, job.ReserveValue, job.OtherOrigValues, job.Spray)

            // যদি stopping সেট করা হয়ে থাকে, আমরা নেভিগেটও না করবো
            if atomic.LoadInt32(&stopping) == 1 {
                return
            }

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

            // যদি interrupt এসেছে, তাহলে কোন প্রিন্ট/রেজাল্ট না করে exit করো
            if atomic.LoadInt32(&stopping) == 1 {
                return
            }

            // prepare label: spray হলে (totalParams) দেখাবে, না হলে আগের মত param name with color
            var label string
            if job.Spray {
                label = fmt.Sprintf("(%d)", job.TotalParam)
            } else {
                label = fmt.Sprintf("(%s%s%s)", skyblue, job.TargetParam, reset)
            }

            // handle results & print
            if err != nil && !found {
                if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
                    atomic.AddInt64(&totalTimeout, 1)
                } else {
                    atomic.AddInt64(&totalError, 1)
                }
                if atomic.LoadInt32(&stopping) == 1 {
                    return
                }
                if silentOnly {
                    fmt.Printf("%s%s%s\n", white, mutated, reset)
                } else {
                    fmt.Printf("[%d/%d] Not Vulnerable %s: %s\n\n", job.IdxURL, job.TotalURLs, label, mutated)
                }
                return
            }

            if found {
                atomic.AddInt64(&totalXSSFound, 1)
                if atomic.LoadInt32(&stopping) == 1 {
                    return
                }
                if silentOnly {
                    fmt.Printf("%s%s%s\n", red, foundURL, reset)
                } else {
                    fmt.Printf("[%d/%d] XSS Found %s: %s%s%s\n\n", job.IdxURL, job.TotalURLs, label, red, foundURL, reset)
                }
                // ফলাফল রেজাল্ট চ্যানেলে পাঠানোর আগে আবার চেক
                if atomic.LoadInt32(&stopping) == 1 {
                    return
                }
                results <- foundURL
            } else {
                if atomic.LoadInt32(&stopping) == 1 {
                    return
                }
                if silentOnly {
                    fmt.Printf("%s%s%s\n", white, mutated, reset)
                } else {
                    fmt.Printf("[%d/%d] Not Vulnerable %s: %s\n\n", job.IdxURL, job.TotalURLs, label, mutated)
                }
            }
        }()
    }
}
