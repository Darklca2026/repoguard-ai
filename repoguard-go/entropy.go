package main

import (
	"math"
)

// CalculateShannonEntropy uses a low-level approach with minimal allocations
// to quickly calculate the Shannon entropy of a given byte slice.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Lookup array for counts avoids heavy memory allocation per string
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range counts {
		if count > 0 {
			p := float64(count) / length
			// math.Log2 is fast in Go
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
