package main

import (
    "context"

    "github.com/chromedp/chromedp"
)

var ChromePath = "/usr/bin/google-chrome"

func CreateSharedAllocator(ctx context.Context, chromePath string) (context.Context, context.CancelFunc, error) {
    opts := append(chromedp.DefaultExecAllocatorOptions[:],
        chromedp.ExecPath(chromePath),
        chromedp.Flag("headless", true),
        chromedp.Flag("disable-gpu", true),
        chromedp.Flag("no-sandbox", true),
        chromedp.Flag("disable-dev-shm-usage", true),
        chromedp.Flag("disable-popup-blocking", true),
        chromedp.Flag("disable-images", true),                  // ছবি লোড বন্ধ
        // chromedp.Flag("blink-settings", "imagesEnabled=false"), // ছবি রেন্ডারিং বন্ধ
        chromedp.Flag("disable-extensions", true),              // এক্সটেনশন বন্ধ
        chromedp.Flag("disable-background-networking", true),   // ব্যাকগ্রাউন্ড নেটওয়ার্ক বন্ধ
        chromedp.Flag("disable-client-side-phishing-detection", true), // ফিশিং ডিটেকশন বন্ধ
        chromedp.Flag("disable-hang-monitor", true),            // হ্যাং মনিটরিং বন্ধ
    )
    allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
    return allocCtx, cancel, nil
}