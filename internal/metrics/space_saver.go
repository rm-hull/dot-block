package metrics

import (
	"sort"
	"sync"
)

type SpaceSaverEntry struct {
	Key   string
	Count int
	Error int
}

type SpaceSaver struct {
	k       int
	entries map[string]*SpaceSaverEntry
	mu      sync.Mutex

	minKey string // cached key with minimum Count; "" when unknown
}

// NewSpaceSaver creates a new tracker with space for k items.
func NewSpaceSaver(k int) *SpaceSaver {
	return &SpaceSaver{
		k:       k,
		entries: make(map[string]*SpaceSaverEntry, k),
		minKey:  "",
	}
}

func (s *SpaceSaver) recomputeMinLocked() {
	if len(s.entries) == 0 {
		s.minKey = ""
		return
	}
	minK := ""
	minC := int(^uint(0) >> 1)
	for k, e := range s.entries {
		if e.Count < minC {
			minC = e.Count
			minK = k
		}
	}
	s.minKey = minK
}

// Add records an occurrence of key.
func (s *SpaceSaver) Add(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Case 1: key is already being tracked
	if e, ok := s.entries[key]; ok {
		e.Count++
		// if key was the min, incrementing it may invalidate min -> recompute
		if s.minKey == key {
			s.recomputeMinLocked()
		}
		return
	}

	// Case 2: there’s still room
	if len(s.entries) < s.k {
		s.entries[key] = &SpaceSaverEntry{Key: key, Count: 1}
		// update cached min
		if minEntry, ok := s.entries[s.minKey]; !ok || minEntry.Count > 1 {
			s.minKey = key
		}
		return
	}

	// Case 3: full – replace smallest
	// Ensure minKey is valid
	if _, ok := s.entries[s.minKey]; !ok {
		s.recomputeMinLocked()
	}
	minEntry := s.entries[s.minKey]
	delete(s.entries, s.minKey)

	// Insert new key using minEntry.Count as error
	s.entries[key] = &SpaceSaverEntry{
		Key:   key,
		Count: minEntry.Count + 1,
		Error: minEntry.Count,
	}

	// cached min is now invalid -> recompute once
	s.recomputeMinLocked()
}

// TopN returns the current top-n items (sorted by count desc).
func (s *SpaceSaver) TopN(n int) []SpaceSaverEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	all := make([]SpaceSaverEntry, 0, len(s.entries))
	for _, e := range s.entries {
		all = append(all, *e)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Count > all[j].Count
	})

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}
