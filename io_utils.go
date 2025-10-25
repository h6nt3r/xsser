package main

import (
    "bufio"
    "os"
    "strings"
)

func ReadLines(path string) ([]string, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    sc := bufio.NewScanner(f)
    var lines []string
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" {
            continue
        }
        lines = append(lines, line)
    }
    if err := sc.Err(); err != nil {
        return nil, err
    }
    return lines, nil
}

func ReadStdinLines() ([]string, error) {
    fi, err := os.Stdin.Stat()
    if err != nil {
        return nil, err
    }
    if (fi.Mode() & os.ModeCharDevice) != 0 {
        return nil, nil
    }
    sc := bufio.NewScanner(os.Stdin)
    var lines []string
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" {
            continue
        }
        lines = append(lines, line)
    }
    if err := sc.Err(); err != nil {
        return nil, err
    }
    return lines, nil
}

func buildMutatedURLWithReserve(rawURL string, paramsOrder []string, targetParam, payload, reserveValue string, otherOrig map[string]string) string {
    prefix := rawURL
    if idx := strings.Index(rawURL, "?"); idx >= 0 {
        prefix = rawURL[:idx]
    }
    var parts []string
    for _, k := range paramsOrder {
        v := reserveValue
        if k == targetParam {
            v = payload
        }
        if k != targetParam && otherOrig != nil {
            if ov, ok := otherOrig[k]; ok {
                v = ov
            }
        }
        parts = append(parts, k+"="+v)
    }
    if strings.Contains(rawURL, "?") {
        return prefix + "?" + strings.Join(parts, "&")
    }
    return prefix + "?" + strings.Join(parts, "&")
}