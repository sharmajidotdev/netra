package test

import (
	"context"
	"testing"

	"github.com/sharmajidotdev/netra/internal/scanner"
)

func TestScanEmpty(t *testing.T) {
	s := scanner.New()
	res, err := s.Scan(context.Background(), "test/fixtures/aws_key.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(res.Findings))
	}
}
