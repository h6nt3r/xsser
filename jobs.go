package main

import (
    "context"
    "net/url"
    "strings"
)
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
    Encoding        string
    IdxEncoding     int
    Spray           bool // 🔥 নতুন ফিল্ড — spray mode এর জন্য
}



// --- তারপর এখানে থাকবে BuildJobs() এবং StreamJobs() ---

// --- paste/replace BuildJobs and StreamJobs in jobs.go ---

// BuildJobs creates a list of jobs from URLs and payloads
// Behavior for spray=true (updated):
//   - iterate over URLs (outer loop) and assign payload = payloads[uIdx % len(payloads)]
//   - meaning if urls > payloads, payload list will wrap and reuse payloads from start
//   - one job per URL per encoding (job.Spray = true)
func BuildJobs(urls []string, payloads []string, paramFilter string, encodings []string, spray bool) ([]Job, error) {
	var jobsList []Job

	if len(urls) == 0 {
		return jobsList, nil
	}

	// parse urls once
	type urlMeta struct {
		raw        string
		params     []string
		origValues map[string]string
	}
	metas := make([]urlMeta, 0, len(urls))
	for _, raw := range urls {
		parsed, _ := url.Parse(raw)
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

		metas = append(metas, urlMeta{
			raw:        raw,
			params:     params,
			origValues: origValues,
		})
	}

	// spray mode: ITERATE URLs, payloads cycle
	if spray {
		if len(payloads) == 0 {
			return jobsList, nil
		}
		encodingList := []string{""}
		if len(encodings) > 0 {
			encodingList = encodings
		}

		for uIdx, meta := range metas {
			if len(meta.params) == 0 {
				continue
			}

			// paramFilter: require at least one param's original value contains the filter
			if paramFilter != "" {
				okAny := false
				for _, k := range meta.params {
					if ov, ok := meta.origValues[k]; ok {
						if strings.Contains(ov, paramFilter) {
							okAny = true
							break
						}
					}
				}
				if !okAny {
					continue
				}
			}

			// choose payload cyclically for this URL
			payload := payloads[uIdx%len(payloads)]

			reserveValue := ""
			if v, ok := meta.origValues[meta.params[0]]; ok {
				reserveValue = v
			}

			for ei, encoding := range encodingList {
				encodedPayload := EncodePayload(payload, encoding)
				otherCopy := make(map[string]string, len(meta.origValues))
				for kk, vv := range meta.origValues {
					otherCopy[kk] = vv
				}

				j := Job{
					OriginalURL:     meta.raw,
					TargetParam:     meta.params[0], // label only; worker will apply to all params when Spray==true
					Payload:         encodedPayload,
					ReserveValue:    reserveValue,
					TargetOrigValue: meta.origValues[meta.params[0]],
					ParamsOrder:     meta.params,
					OtherOrigValues: otherCopy,
					IdxURL:          uIdx + 1,
					TotalURLs:       len(urls),
					IdxParam:        1,
					TotalParam:      len(meta.params),
					IdxPayload:      (uIdx % len(payloads)) + 1, // index of payload used
					TotalPay:        len(payloads),
					Encoding:        encoding,
					IdxEncoding:     ei + 1,
					Spray:           true,
				}
				jobsList = append(jobsList, j)
			}
		}

		return jobsList, nil
	}

	// non-spray (original) behavior unchanged
	for ui, meta := range metas {
		if len(meta.params) == 0 {
			continue
		}

		reserveValue := ""
		if v, ok := meta.origValues[meta.params[0]]; ok {
			reserveValue = v
		}
		prevReserve := reserveValue

		for pi, param := range meta.params {
			if paramFilter != "" {
				ov := ""
				if v, ok := meta.origValues[param]; ok {
					ov = v
				}
				if !strings.Contains(ov, paramFilter) {
					continue
				}
			}

			origVal := ""
			if v, ok := meta.origValues[param]; ok {
				origVal = v
			}
			currReserve := prevReserve

			encodingList := []string{""}
			if len(encodings) > 0 {
				encodingList = encodings
			}

			for xi, payload := range payloads {
				for ei, encoding := range encodingList {
					encodedPayload := EncodePayload(payload, encoding)
					otherCopy := make(map[string]string, len(meta.origValues))
					for kk, vv := range meta.origValues {
						otherCopy[kk] = vv
					}

					j := Job{
						OriginalURL:     meta.raw,
						TargetParam:     param,
						Payload:         encodedPayload,
						ReserveValue:    currReserve,
						TargetOrigValue: origVal,
						ParamsOrder:     meta.params,
						OtherOrigValues: otherCopy,
						IdxURL:          ui + 1,
						TotalURLs:       len(urls),
						IdxParam:        pi + 1,
						TotalParam:      len(meta.params),
						IdxPayload:      xi + 1,
						TotalPay:        len(payloads),
						Encoding:        encoding,
						IdxEncoding:     ei + 1,
						Spray:           false,
					}
					jobsList = append(jobsList, j)
				}
			}

			prevReserve = origVal
		}
	}

	return jobsList, nil
}

// StreamJobs streams jobs into provided jobs channel (context-aware).
// Updated spray behavior: iterate URLs and pick payload = payloads[uIdx % len(payloads)]
func StreamJobs(ctx context.Context, urls []string, payloads []string, paramFilter string, encodings []string, spray bool, jobs chan<- Job) error {
	// quick sanity
	if len(urls) == 0 {
		return nil
	}

	type urlMeta struct {
		raw        string
		params     []string
		origValues map[string]string
	}
	metas := make([]urlMeta, 0, len(urls))
	for _, raw := range urls {
		parsed, _ := url.Parse(raw)
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
		metas = append(metas, urlMeta{raw: raw, params: params, origValues: origValues})
	}

	encodingList := []string{""}
	if len(encodings) > 0 {
		encodingList = encodings
	}

	if spray {
		if len(payloads) == 0 {
			return nil
		}
		for uIdx, meta := range metas {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if len(meta.params) == 0 {
				continue
			}

			// paramFilter: require at least one param orig value contain the filter
			if paramFilter != "" {
				okAny := false
				for _, k := range meta.params {
					if ov, ok := meta.origValues[k]; ok {
						if strings.Contains(ov, paramFilter) {
							okAny = true
							break
						}
					}
				}
				if !okAny {
					continue
				}
			}

			// choose payload cyclically for this URL
			payload := payloads[uIdx%len(payloads)]

			reserveValue := ""
			if v, ok := meta.origValues[meta.params[0]]; ok {
				reserveValue = v
			}

			for ei, encoding := range encodingList {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				encodedPayload := EncodePayload(payload, encoding)
				otherCopy := make(map[string]string, len(meta.origValues))
				for kk, vv := range meta.origValues {
					otherCopy[kk] = vv
				}
				j := Job{
					OriginalURL:     meta.raw,
					TargetParam:     meta.params[0],
					Payload:         encodedPayload,
					ReserveValue:    reserveValue,
					TargetOrigValue: meta.origValues[meta.params[0]],
					ParamsOrder:     meta.params,
					OtherOrigValues: otherCopy,
					IdxURL:          uIdx + 1,
					TotalURLs:       len(urls),
					IdxParam:        1,
					TotalParam:      len(meta.params),
					IdxPayload:      (uIdx % len(payloads)) + 1,
					TotalPay:        len(payloads),
					Encoding:        encoding,
					IdxEncoding:     ei + 1,
					Spray:           true,
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				case jobs <- j:
				}
			}
		}
		return nil
	}

	// non-spray streaming unchanged
	for ui, meta := range metas {
		if len(meta.params) == 0 {
			continue
		}
		reserveValue := ""
		if v, ok := meta.origValues[meta.params[0]]; ok {
			reserveValue = v
		}
		prevReserve := reserveValue
		for pi, param := range meta.params {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if paramFilter != "" {
				ov := ""
				if v, ok := meta.origValues[param]; ok {
					ov = v
				}
				if !strings.Contains(ov, paramFilter) {
					continue
				}
			}
			origVal := ""
			if v, ok := meta.origValues[param]; ok {
				origVal = v
			}
			currReserve := prevReserve
			for xi, payload := range payloads {
				for ei, encoding := range encodingList {
					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
					}
					encodedPayload := EncodePayload(payload, encoding)
					otherCopy := make(map[string]string, len(meta.origValues))
					for kk, vv := range meta.origValues {
						otherCopy[kk] = vv
					}
					j := Job{
						OriginalURL:     meta.raw,
						TargetParam:     param,
						Payload:         encodedPayload,
						ReserveValue:    currReserve,
						TargetOrigValue: origVal,
						ParamsOrder:     meta.params,
						OtherOrigValues: otherCopy,
						IdxURL:          ui + 1,
						TotalURLs:       len(urls),
						IdxParam:        pi + 1,
						TotalParam:      len(meta.params),
						IdxPayload:      xi + 1,
						TotalPay:        len(payloads),
						Encoding:        encoding,
						IdxEncoding:     ei + 1,
						Spray:           false,
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case jobs <- j:
					}
				}
			}
			prevReserve = origVal
		}
	}
	return nil
}
