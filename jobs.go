package main

import (
	"context"
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
	Encoding        string // encoding type
	IdxEncoding     int    // encoding index
	Spray           bool   // spray mode for this job
}

// BuildJobs kept for compatibility (you can keep or ignore if using StreamJobs)
func BuildJobs(urls []string, payloads []string, paramFilter string, encodings []string, spray bool) ([]Job, error) {
	// simple wrapper that calls Stream-style builder into a slice (careful with memory)
	var jobs []Job
	if len(urls) == 0 {
		return jobs, nil
	}

	// reuse StreamJobs logic but accumulate
	// parse url metas
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

	// spray mode: iterate payloads cyclically across urls
	if spray {
		if len(payloads) == 0 {
			return jobs, nil
		}
		encodingList := []string{""}
		if len(encodings) > 0 {
			encodingList = encodings
		}
		for pIdx, payload := range payloads {
			uIdx := pIdx % len(metas)
			meta := metas[uIdx]
			if len(meta.params) == 0 {
				continue
			}
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
					IdxPayload:      pIdx + 1,
					TotalPay:        len(payloads),
					Encoding:        encoding,
					IdxEncoding:     ei + 1,
					Spray:           true,
				}
				jobs = append(jobs, j)
			}
		}
		return jobs, nil
	}

	// non-spray: classic expansion (careful: may use lots of memory)
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
					jobs = append(jobs, j)
				}
			}
			prevReserve = origVal
		}
	}
	return jobs, nil
}

// StreamJobs streams jobs into provided jobs channel (context-aware).
// Use StreamJobs to avoid huge memory spikes.
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
		for pIdx, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			uIdx := pIdx % len(metas)
			meta := metas[uIdx]
			if len(meta.params) == 0 {
				continue
			}
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
					IdxPayload:      pIdx + 1,
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

	// non-spray streaming
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
