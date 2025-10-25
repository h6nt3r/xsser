package main

import (
    "net/url"
    "strings"
)

// Job struct holds the necessary fields for XSS scanning jobs
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
    Encoding        string // এনকোডিং টাইপ
    IdxEncoding     int    // নতুন ফিল্ড: এনকোডিং ইনডেক্স
}

// BuildJobs creates a list of jobs from URLs and payloads
func BuildJobs(urls []string, payloads []string, paramFilter string, encodings []string) ([]Job, error) {
    var jobsList []Job

    for ui, raw := range urls {
        parsed, err := url.Parse(raw)
        _ = err
        params := []string{}
        origValues := map[string]string{}

        if parsed != nil && parsed.RawQuery != "" {
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
            if paramFilter != "" {
                ov := ""
                if v, ok := origValues[param]; ok {
                    ov = v
                }
                if !strings.Contains(ov, paramFilter) {
                    continue
                }
            }

            origVal := ""
            if v, ok := origValues[param]; ok {
                origVal = v
            }
            currReserve := prevReserve

            for xi, payload := range payloads {
                // যদি কোনো এনকোডিং না দেওয়া থাকে, তাহলে শুধু মূল পেলোড ব্যবহার করো
                encodingList := []string{""} // ডিফল্ট: কোনো এনকোডিং নয়
                if len(encodings) > 0 {
                    encodingList = encodings
                }

                for ei, encoding := range encodingList {
                    encodedPayload := EncodePayload(payload, encoding)
                    otherCopy := make(map[string]string, len(origValues))
                    for kk, vv := range origValues {
                        otherCopy[kk] = vv
                    }

                    j := Job{
                        OriginalURL:     raw,
                        TargetParam:     param,
                        Payload:         encodedPayload,
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
                        Encoding:        encoding,
                        IdxEncoding:     ei + 1, // এনকোডিং ইনডেক্স
                    }
                    jobsList = append(jobsList, j)
                }
            }

            prevReserve = origVal
        }
    }

    return jobsList, nil
}