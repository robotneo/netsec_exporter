package client

import (
	"crypto/md5"
	"fmt"
	"testing"
	"time"
)

func TestACClientSignedParamsAreCachedForOneHour(t *testing.T) {
	c := &ACClient{SharedKey: "Mkld@2026"}

	random1, md51, err := c.nextSignedParams()
	if err != nil {
		t.Fatalf("first nextSignedParams failed: %v", err)
	}
	if len(random1) != 8 {
		t.Fatalf("expected 8-digit random, got %q", random1)
	}
	for _, ch := range random1 {
		if ch < '0' || ch > '9' {
			t.Fatalf("expected numeric random, got %q", random1)
		}
	}

	wantMD5 := fmt.Sprintf("%x", md5.Sum([]byte("Mkld@2026"+random1)))
	if md51 != wantMD5 {
		t.Fatalf("expected md5 %q, got %q", wantMD5, md51)
	}

	random2, md52, err := c.nextSignedParams()
	if err != nil {
		t.Fatalf("second nextSignedParams failed: %v", err)
	}
	if random2 != random1 || md52 != md51 {
		t.Fatalf("expected cached params to be reused within one hour")
	}
}

func TestACClientSignedParamsRefreshWhenKeyChanges(t *testing.T) {
	c := &ACClient{
		SharedKey:    "old-key",
		cachedKey:    "old-key",
		cachedRandom: "12345678",
		cachedMD5:    fmt.Sprintf("%x", md5.Sum([]byte("old-key12345678"))),
		cachedUntil:  time.Now().Add(time.Hour),
	}

	random, md5hex, err := c.nextSignedParams()
	if err != nil {
		t.Fatalf("initial nextSignedParams failed: %v", err)
	}
	if random != "12345678" {
		t.Fatalf("expected existing cached random to be reused, got %q", random)
	}

	c.SharedKey = "new-key"
	random2, md5hex2, err := c.nextSignedParams()
	if err != nil {
		t.Fatalf("nextSignedParams after key change failed: %v", err)
	}
	if random2 == random && md5hex2 == md5hex {
		t.Fatalf("expected cached params to be refreshed after shared key change")
	}

	wantMD5 := fmt.Sprintf("%x", md5.Sum([]byte("new-key"+random2)))
	if md5hex2 != wantMD5 {
		t.Fatalf("expected md5 %q, got %q", wantMD5, md5hex2)
	}
}
