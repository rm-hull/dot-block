package noisefilter

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"sync"
)

type Triplet struct {
	Category     string
	Rcode        string
	DomainSuffix string
}

type NoiseFilter struct {
	mu       sync.RWMutex
	triplets []Triplet
}

func NewNoiseFilter() *NoiseFilter {
	return &NoiseFilter{
		triplets: make([]Triplet, 0),
	}
}

func (nf *NoiseFilter) Reset() {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.triplets = make([]Triplet, 0)
}

func (nf *NoiseFilter) Load(reader io.Reader) error {
	csvReader := csv.NewReader(reader)

	// Detect and skip header
	_, err := csvReader.Read()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("failed to read CSV: %w", err)
	}

	nf.mu.Lock()
	defer nf.mu.Unlock()

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV record: %w", err)
		}

		if len(record) < 3 {
			continue // Skip malformed lines
		}

		nf.appendTriplet(record)
	}

	return nil
}

func (nf *NoiseFilter) appendTriplet(record []string) {
	suffix := strings.TrimSpace(record[2])
	if suffix != "" && !strings.HasSuffix(suffix, ".") {
		suffix += "."
	}

	nf.triplets = append(nf.triplets, Triplet{
		Category:     strings.ToUpper(strings.TrimSpace(record[0])),
		Rcode:        strings.ToUpper(strings.TrimSpace(record[1])),
		DomainSuffix: suffix,
	})
}

func (nf *NoiseFilter) ShouldSuppress(category, rcode, domain string) bool {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	category = strings.ToUpper(category)
	rcode = strings.ToUpper(rcode)

	nf.mu.RLock()
	defer nf.mu.RUnlock()

	for _, t := range nf.triplets {
		if t.Category == category && t.Rcode == rcode {
			if domain == t.DomainSuffix || strings.HasSuffix(domain, "."+t.DomainSuffix) {
				return true
			}
		}
	}

	return false
}
