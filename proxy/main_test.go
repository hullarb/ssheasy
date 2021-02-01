package main

import (
	"bytes"
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	freeLimit = 100
	maxLimitedRate = 10
	maxBurst = 5

	w1, w2 := new(bytes.Buffer), new(bytes.Buffer)
	l := newLogger()
	lw1, lw2 := newLimters(w1, w2, l)

	s := time.Now()
	// free limit applies separate for both writer + burst shared
	for i := 0; i < 52; i++ {
		lw1.Write([]byte{byte(i), byte(i + 1)})
		lw2.Write([]byte{byte(i), byte(i + 1)})
	}
	if d := time.Now().Sub(s); d > 3*time.Millisecond {
		t.Errorf("free limit not kept: %v", d)
	}

	s = time.Now()
	lw1.Write([]byte{1, 2, 3})
	if d := time.Now().Sub(s); d < 200*time.Millisecond {
		t.Errorf("1st writer is not limited: %v", d)
	}

	s = time.Now()
	lw2.Write([]byte{1, 2, 3})
	if d := time.Now().Sub(s); d < 200*time.Millisecond {
		t.Errorf("2nd writer is not limited: %v", d)
	}
}
