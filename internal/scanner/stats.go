package scanner

import (
	"sync/atomic"
	"time"
)

// Stats tracks scanning statistics
type Stats struct {
	FilesScanned int32
	FilesSkipped int32
	BytesScanned int64
	Findings     int32
	Duration     int64
}

// newStats creates new statistics tracker
func newStats() *Stats {
	return &Stats{}
}

// reset resets all statistics to zero
func (s *Stats) reset() {
	atomic.StoreInt32(&s.FilesScanned, 0)
	atomic.StoreInt32(&s.FilesSkipped, 0)
	atomic.StoreInt64(&s.BytesScanned, 0)
	atomic.StoreInt32(&s.Findings, 0)
	atomic.StoreInt64(&s.Duration, 0)
}

// addFileScanned increments scanned files counter
func (s *Stats) addFileScanned() {
	atomic.AddInt32(&s.FilesScanned, 1)
}

// addFileSkipped increments skipped files counter
func (s *Stats) addFileSkipped() {
	atomic.AddInt32(&s.FilesSkipped, 1)
}

// addBytesScanned adds to the total bytes scanned
func (s *Stats) addBytesScanned(n int64) {
	atomic.AddInt64(&s.BytesScanned, n)
}

// addFindings increments findings counter
func (s *Stats) addFindings(n int) {
	atomic.AddInt32(&s.Findings, int32(n))
}

// setDuration sets the total scan duration
func (s *Stats) setDuration(d time.Duration) {
	atomic.StoreInt64(&s.Duration, int64(d))
}

// toMap converts stats to a map for reporting
func (s *Stats) toMap() map[string]interface{} {
	return map[string]interface{}{
		"files_scanned": atomic.LoadInt32(&s.FilesScanned),
		"files_skipped": atomic.LoadInt32(&s.FilesSkipped),
		"bytes_scanned": atomic.LoadInt64(&s.BytesScanned),
		"findings":      atomic.LoadInt32(&s.Findings),
		"duration_ms":   atomic.LoadInt64(&s.Duration),
	}
}
