//go:build race

package analyzer

// raceDetector says that the tests run with the race detector, which makes
// the analysis several times slower.
const raceDetector = true
