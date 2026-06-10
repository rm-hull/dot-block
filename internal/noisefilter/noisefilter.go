package noisefilter

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
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

func (nf *NoiseFilter) Load(reader io.Reader) error {
	csvReader := csv.NewReader(reader)
	
	// Skip header
	if _, err := csvReader.Read(); err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	var newTriplets []Triplet
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

		newTriplets = append(newTriplets, Triplet{
			Category:     strings.TrimSpace(record[0]),
			Rcode:        strings.TrimSpace(record[1]),
			DomainSuffix: strings.TrimSpace(record[2]),
		})
	}

	nf.mu.Lock()
	nf.triplets = newTriplets
	nf.mu.Unlock()

	return nil
}

func (nf *NoiseFilter) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return nf.Load(f)
}

func (nf *NoiseFilter) ShouldSuppress(category, rcode, domain string) bool {
	nf.mu.RLock()
	defer nf.mu.RUnlock()

	for _, t := range nf.triplets {
		if t.Category == category && t.Rcode == rcode && strings.HasSuffix(domain, t.DomainSuffix) {
			return true
		}
	}

	return false
}
