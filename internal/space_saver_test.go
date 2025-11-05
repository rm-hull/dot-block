package internal

import (
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSpaceSaver(t *testing.T) {
	assert := assert.New(t)

	ss := NewSpaceSaver(5)
	assert.NotNil(ss, "NewSpaceSaver returned nil")
	assert.Equal(5, ss.k, "Expected k to be 5")
	assert.NotNil(ss.entries, "Entries map is nil")
	assert.Empty(ss.entries, "Expected entries map to be empty")
	assert.Empty(ss.minKey, "Expected minKey to be empty")
}

func TestSpaceSaverAdd(t *testing.T) {
	assert := assert.New(t)

	ss := NewSpaceSaver(3) // k = 3

	// Add items, not exceeding k
	ss.Add("apple")
	ss.Add("banana")
	ss.Add("apple")

	expected := map[string]*SpaceSaverEntry{
		"apple":  {Key: "apple", Count: 2, Error: 0},
		"banana": {Key: "banana", Count: 1, Error: 0},
	}

	assert.Len(ss.entries, 2, "Expected 2 entries")
	for k, v := range expected {
		entry, ok := ss.entries[k]
		assert.True(ok, "Expected key %s not found", k)
		assert.Equal(v.Key, entry.Key)
		assert.Equal(v.Count, entry.Count)
		assert.Equal(v.Error, entry.Error)
	}

	// Add items, exceeding k, forcing replacement
	ss.Add("orange") // apple:2, banana:1, orange:1
	ss.Add("grape")  // apple:2, orange:1, grape:1 (banana replaced)

	assert.Len(ss.entries, 3, "Expected 3 entries after replacement")

	// Check counts for known items
	appleEntry, ok := ss.entries["apple"]
	assert.True(ok, "Apple entry not found")
	assert.GreaterOrEqual(appleEntry.Count, 2, "Apple count incorrect")

	grapeEntry, ok := ss.entries["grape"]
	assert.True(ok, "Grape entry not found")
	assert.GreaterOrEqual(grapeEntry.Count, 1, "Grape count incorrect")

	_, ok = ss.entries["banana"]
	assert.False(ok, "Banana should have been replaced")

	// Test adding an existing item when full
	ss.Add("apple") // apple:3, orange:1, grape:1
	appleEntry, ok = ss.entries["apple"]
	assert.True(ok, "Apple entry not found after increment")
	assert.Equal(3, appleEntry.Count, "Apple count incorrect after increment")

	// Test adding a new item when full, with error propagation
	// Current: apple:3, orange:1, grape:1. minKey could be orange or grape.
	// Let's assume orange is replaced.
	ss.Add("kiwi") // apple:3, grape:1, kiwi: (minCount+1)
	_, ok = ss.entries["kiwi"]
	assert.True(ok, "Kiwi should have been added")

	// Check that one of the original low-count items is gone
	// This part is tricky due to the non-deterministic nature of map iteration
	// and which minKey is chosen if counts are equal. We'll check that the total
	// number of entries is still k and that the counts are reasonable.
	assert.Len(ss.entries, 3, "Expected 3 entries after adding kiwi")

	// Verify that the sum of counts is consistent with additions and errors
	// This is a more robust check for SpaceSaver's behavior when full.
	initialAdds := 5 // apple, banana, apple, orange, grape
	finalAdds := 2   // apple, kiwi
	totalAdds := initialAdds + finalAdds

	sumCounts := 0
	for _, entry := range ss.entries {
		sumCounts += entry.Count
	}
	// The sum of counts should be >= totalAdds, as errors add to counts.
	assert.GreaterOrEqual(sumCounts, totalAdds, "Sum of counts should be greater or equal to total adds")

	// --- Additional tests for Case 3 (replacement when full) ---
	t.Run("Case3_ReplacementDetails", func(t *testing.T) {

		ss := NewSpaceSaver(2) // k = 2
		ss.Add("a")            // a:1
		ss.Add("b")            // a:1, b:1

		// Add "c", which should replace one of "a" or "b"
		ss.Add("c") // e.g., b replaced. a:1, c: (b.Count + 1), Error: b.Count

		assert.Len(ss.entries, 2, "Expected 2 entries after replacement")
		_, foundA := ss.entries["a"]
		_, foundB := ss.entries["b"]
		_, foundC := ss.entries["c"]

		assert.True(foundC, "New key 'c' should be present")
		assert.True(foundA || foundB, "Either 'a' or 'b' should still be present")
		assert.False(foundA && foundB, "Only one of 'a' or 'b' should be present")

		// Check the replaced entry's error and count
		if entryC, ok := ss.entries["c"]; ok {
			// The replaced entry had count 1. So new entry 'c' should have Count 2, Error 1.
			assert.Equal(2, entryC.Count, "Expected count for 'c' to be 2")
			assert.Equal(1, entryC.Error, "Expected error for 'c' to be 1")
		}

		// Add another item, ensuring minKey recomputation works
		ss.Add("d") // e.g., a replaced. c:2, d: (a.Count + 1), Error: a.Count

		assert.Len(ss.entries, 2, "Expected 2 entries after second replacement")
		_, foundD := ss.entries["d"]
		assert.True(foundD, "New key 'd' should be present")

		// Check counts and errors again
		if entryD, ok := ss.entries["d"]; ok {
			// The replaced entry (either 'a' or 'b') had count 1. So new entry 'd' should have Count 2, Error 1.
			assert.Equal(2, entryD.Count, "Expected count for 'd' to be 2")
			assert.Equal(1, entryD.Error, "Expected error for 'd' to be 1")
		}
	})
}

func TestSpaceSaverTopN(t *testing.T) {
	assert := assert.New(t)

	ss := NewSpaceSaver(5)
	ss.Add("apple")
	ss.Add("banana")
	ss.Add("apple")
	ss.Add("orange")
	ss.Add("banana")
	ss.Add("banana")
	ss.Add("grape")
	ss.Add("apple")

	// Current state (k=5, so no replacements yet):
	// banana: 3
	// apple:  3
	// orange: 1
	// grape:  1

	top2 := ss.TopN(2)
	assert.Len(top2, 2, "Expected 2 items in TopN(2)")

	// Sort by key for consistent comparison if counts are equal
	sort.Slice(top2, func(i, j int) bool {
		return top2[i].Key < top2[j].Key
	})

	// Since apple and banana both have count 3, their order might vary.
	// We check for their presence and counts.
	foundApple := false
	foundBanana := false
	for _, entry := range top2 {
		if entry.Key == "apple" && entry.Count == 3 {
			foundApple = true
		}
		if entry.Key == "banana" && entry.Count == 3 {
			foundBanana = true
		}
	}
	assert.True(foundApple, "Expected apple in top 2 with count 3")
	assert.True(foundBanana, "Expected banana in top 2 with count 3")

	topAll := ss.TopN(10) // Request more than available
	assert.Len(topAll, 4, "Expected 4 items in TopN(10)")

	// Verify sorting order (descending count)
	assert.GreaterOrEqual(topAll[0].Count, topAll[1].Count, "TopN items not sorted correctly")
	assert.GreaterOrEqual(topAll[1].Count, topAll[2].Count, "TopN items not sorted correctly")
	assert.GreaterOrEqual(topAll[2].Count, topAll[3].Count, "TopN items not sorted correctly")

	// Test with an empty SpaceSaver
	emptySS := NewSpaceSaver(2)
	emptyTopN := emptySS.TopN(1)
	assert.Empty(emptyTopN, "Expected empty TopN for empty SpaceSaver")

	// --- Additional tests for TopN ---
	t.Run("TopN_WithReplacements", func(t *testing.T) {

		ss := NewSpaceSaver(2) // k = 2
		ss.Add("a")            // a:1
		ss.Add("b")            // a:1, b:1
		ss.Add("c")            // c:2, (a or b replaced), Error: 1
		ss.Add("a")            // a:1 (if b was replaced) or a:2 (if a was kept and incremented)
		// This scenario is tricky due to non-deterministic replacement.
		// Let's ensure the top item is correct and the list is sorted.

		// To make it deterministic for testing, let's add more items to ensure a clear top.
		ss = NewSpaceSaver(2)
		ss.Add("item1")
		ss.Add("item2")
		ss.Add("item1") // item1:2, item2:1
		ss.Add("item3") // item1:2, item3: (item2.Count+1)=2, Error:1 (item2 replaced)
		ss.Add("item1") // item1:3, item3:2

		topN := ss.TopN(1)
		assert.Len(topN, 1)
		assert.Equal("item1", topN[0].Key)
		assert.Equal(3, topN[0].Count)

		topN = ss.TopN(2)
		assert.Len(topN, 2)
		assert.Equal("item1", topN[0].Key)
		assert.Equal(3, topN[0].Count)
		assert.Equal("item3", topN[1].Key)
		assert.Equal(2, topN[1].Count)

		// Test with all items having same count (after some additions)
		ss = NewSpaceSaver(3)
		ss.Add("x")
		ss.Add("y")
		ss.Add("z")
		ss.Add("x")
		ss.Add("y")
		ss.Add("z") // x:2, y:2, z:2

		topN = ss.TopN(3)
		assert.Len(topN, 3)
		// Order might vary for equal counts, but all should have count 2
		for _, entry := range topN {
			assert.Equal(2, entry.Count)
		}
		// Check keys presence
		keysFound := make(map[string]bool)
		for _, entry := range topN {
			keysFound[entry.Key] = true
		}
		assert.True(keysFound["x"])
		assert.True(keysFound["y"])
		assert.True(keysFound["z"])
	})
}

func TestSpaceSaverConcurrency(t *testing.T) {
	assert := assert.New(t)

	ss := NewSpaceSaver(10)
	keys := []string{"a", "b", "c", "d", "e"}
	numGoroutines := 100
	addsPerGoroutine := 1000

	var wg sync.WaitGroup
	for range numGoroutines {
		wg.Go(func() {
			for j := range addsPerGoroutine {
				ss.Add(keys[j%len(keys)])
			}
		})
	}
	wg.Wait()

	totalExpectedAdds := numGoroutines * addsPerGoroutine
	totalActualCount := 0
	for _, entry := range ss.entries {
		totalActualCount += entry.Count
	}

	// Due to the nature of SpaceSaver, the sum of counts might be slightly higher
	// than totalExpectedAdds because of the error propagation (Count = minCount + 1).
	// However, for k=10 and only 5 distinct keys, all keys should be tracked accurately
	// and the sum of counts should be very close to totalExpectedAdds, if not equal.
	// For this specific test case (k > number of unique keys), the counts should be exact.
	assert.Equal(totalExpectedAdds, totalActualCount, "Expected total count to match total adds")

	// Verify individual counts
	expectedCounts := map[string]int{
		"a": totalExpectedAdds / len(keys),
		"b": totalExpectedAdds / len(keys),
		"c": totalExpectedAdds / len(keys),
		"d": totalExpectedAdds / len(keys),
		"e": totalExpectedAdds / len(keys),
	}

	for k, expectedCount := range expectedCounts {
		entry, ok := ss.entries[k]
		assert.True(ok, "Key %s not found in entries", k)
		assert.Equal(expectedCount, entry.Count, "Key %s: Count mismatch", k)
		assert.Zero(entry.Error, "Key %s: Expected error 0", k) // For k > unique keys, error should be 0
	}
}
