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

// buildMutatedURLWithReserve এখন spray boolean নেয়:
//   - যদি spray == true: সব param-এর value payload হবে
//   - না হলে: পূর্বের আচরণ অনুযায়ী কেবল targetParam-এ payload বসবে, অন্যগুলো reserve/orig অনুযায়ী
func buildMutatedURLWithReserve(rawURL string, paramsOrder []string, targetParam, payload, reserveValue string, otherOrig map[string]string, spray bool) string {
	prefix := rawURL
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		prefix = rawURL[:idx]
	}
	var parts []string
	for _, k := range paramsOrder {
		v := reserveValue

		if spray {
			// spray mode: সব param-এ payload বসাও
			v = payload
		} else {
			// normal behavior: শুধুমাত্র targetParam-এ payload বসবে
			if k == targetParam {
				v = payload
			}
			if k != targetParam && otherOrig != nil {
				if ov, ok := otherOrig[k]; ok {
					v = ov
				}
			}
		}

		parts = append(parts, k+"="+v)
	}
	if strings.Contains(rawURL, "?") {
		return prefix + "?" + strings.Join(parts, "&")
	}
	return prefix + "?" + strings.Join(parts, "&")
}
