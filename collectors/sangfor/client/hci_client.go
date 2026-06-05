package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HCIClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewHCIClient(host string, timeout time.Duration, insecureSkipVerify bool) *HCIClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &HCIClient{
		BaseURL:    fmt.Sprintf("https://%s", strings.TrimSpace(host)),
		HTTPClient: NewHTTPClient(timeout, insecureSkipVerify, true),
	}
}

func (c *HCIClient) GetPublicKeyModulus(ctx context.Context) (string, error) {
	modulus, err := c.getPublicKeyV2(ctx)
	if err == nil && strings.TrimSpace(modulus) != "" {
		return modulus, nil
	}
	modulus, err = c.getPublicKeyV1(ctx)
	if err != nil {
		return "", err
	}
	return modulus, nil
}

func (c *HCIClient) getPublicKeyV2(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/janus/v2/public-key", nil)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("public-key v2 status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var r struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return normalizeHexString(r.PublicKey), nil
}

func (c *HCIClient) getPublicKeyV1(ctx context.Context) (string, error) {
	cookieVal, err := randomHex(16)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/janus/public-key", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Cookie", "aCMPAuthToken="+cookieVal)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("public-key status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var r struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return normalizeHexString(r.PublicKey), nil
}

func (c *HCIClient) DoJSON(ctx context.Context, sess HCISession, method string, path string, reqBody any, out any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}

	u := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Token "+sess.Token)
	if strings.TrimSpace(sess.Cookie) != "" {
		req.Header.Set("Cookie", "aCMPAuthToken="+sess.Cookie)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
