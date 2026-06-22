package client

import (
	"crypto/md5"
	"fmt"
	"testing"
)

func TestACClientSignedParamsUseEightDigitNumericRandom(t *testing.T) {
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
}

func TestACClientSignedParamsRefreshEveryRequest(t *testing.T) {
	c := &ACClient{SharedKey: "Mkld@2026"}

	random1, md51, err := c.nextSignedParams()
	if err != nil {
		t.Fatalf("first nextSignedParams failed: %v", err)
	}
	random2, md52, err := c.nextSignedParams()
	if err != nil {
		t.Fatalf("second nextSignedParams failed: %v", err)
	}
	if random2 == random1 && md52 == md51 {
		t.Fatalf("expected fresh signed params for every request")
	}
}

func TestACClientSignedParamsUseCurrentSharedKey(t *testing.T) {
	c := &ACClient{SharedKey: "old-key"}
	c.SharedKey = "new-key"
	random, md5hex, err := c.nextSignedParams()
	if err != nil {
		t.Fatalf("nextSignedParams failed: %v", err)
	}

	wantMD5 := fmt.Sprintf("%x", md5.Sum([]byte("new-key"+random)))
	if md5hex != wantMD5 {
		t.Fatalf("expected md5 %q, got %q", wantMD5, md5hex)
	}
}
