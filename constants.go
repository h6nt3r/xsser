package main

import (
    "sync/atomic"
    "time"
)

var (
    scanStart time.Time
    // color codes
    red     = "\033[31m"
    skyblue = "\033[36m"
    white   = "\033[37m"
    reset   = "\033[0m"

    // counters
    totalXSSFound int64
    totalTimeout  int64
    totalError    int64
)

func atomicAddInt64(p *int64, delta int64) { atomic.AddInt64(p, delta) }
func atomicLoadInt64(p *int64) int64       { return atomic.LoadInt64(p) }

// silentOnly kept as package-level; updated by ParseFlags
var silentOnly bool