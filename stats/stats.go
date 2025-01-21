package stats

import (
	"math/rand"
	"sort"
)

// Stats is the main struct for statistical calculations
type Stats struct{}

// NewStats creates a new Stats instance
func NewStats() *Stats {
	return &Stats{}
}

// GenerateData generates a slice of random integers within the specified range
func (s *Stats) GenerateData(numberOfValues, minValue, maxValue int) []int {
	values := make([]int, numberOfValues)
	for i := 0; i < numberOfValues; i++ {
		values[i] = rand.Intn(maxValue-minValue+1) + minValue
	}
	return values
}

// GetMean calculates the arithmetic mean of a slice of integers
func (s *Stats) GetMean(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return float64(sum) / float64(len(values))
}

// GetMedian calculates the median value of a slice of integers
func (s *Stats) GetMedian(values []int) float64 {
	if len(values) == 0 {
		return 0
	}

	// Create a copy of the slice to avoid modifying the original
	sortedValues := make([]int, len(values))
	copy(sortedValues, values)
	sort.Ints(sortedValues)

	middleIndex := len(values) / 2
	if len(values)%2 == 0 {
		return float64(sortedValues[middleIndex-1]+sortedValues[middleIndex]) / 2
	}
	return float64(sortedValues[middleIndex])
}

// GetMode returns the most frequent value in a slice of integers
func (s *Stats) GetMode(values []int) int {
	if len(values) == 0 {
		return 0
	}

	// Create a map to count occurrences
	counter := make(map[int]int)
	for _, v := range values {
		counter[v]++
	}

	// Find the highest frequency
	maxCount := 0
	for _, count := range counter {
		if count > maxCount {
			maxCount = count
		}
	}

	return maxCount
}
