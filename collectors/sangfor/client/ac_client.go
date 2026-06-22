package client

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ACClient struct {
	BaseURL    string
	HTTPClient *http.Client
	SharedKey  string
}

func NewACClient(host string, port uint16, timeout time.Duration, insecureSkipVerify bool, sharedKey string) *ACClient {
	if port == 0 {
		port = 9999
	}
	addr := strings.TrimSpace(host)
	if addr == "" {
		addr = "127.0.0.1"
	}
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, port)
	}

	return &ACClient{
		BaseURL:    "http://" + addr,
		HTTPClient: NewHTTPClient(timeout, insecureSkipVerify, false),
		SharedKey:  sharedKey,
	}
}

func (c *ACClient) DoJSON(ctx context.Context, path string, out any) error {
	if strings.TrimSpace(c.SharedKey) == "" {
		return fmt.Errorf("missing shared_key")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	random, md5hex, err := c.nextSignedParams()
	if err != nil {
		return err
	}

	u, err := url.Parse(c.BaseURL + path)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("random", random)
	q.Set("md5", md5hex)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return acHTTPError(resp)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *ACClient) DoJSONPost(ctx context.Context, path string, reqBody any, out any) error {
	if strings.TrimSpace(c.SharedKey) == "" {
		return fmt.Errorf("missing shared_key")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	random, md5hex, err := c.nextSignedParams()
	if err != nil {
		return err
	}

	u, err := url.Parse(c.BaseURL + path)
	if err != nil {
		return err
	}

	bodyMap := map[string]any{}
	if reqBody != nil {
		reqBodyBytes, marshalErr := json.Marshal(reqBody)
		if marshalErr != nil {
			return marshalErr
		}
		if unmarshalErr := json.Unmarshal(reqBodyBytes, &bodyMap); unmarshalErr != nil {
			return unmarshalErr
		}
	}
	bodyMap["random"] = random
	bodyMap["md5"] = md5hex

	b, err := json.Marshal(bodyMap)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "zh-CN")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return acHTTPError(resp)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *ACClient) nextSignedParams() (string, string, error) {
	sharedKey := strings.TrimSpace(c.SharedKey)
	if sharedKey == "" {
		return "", "", fmt.Errorf("missing shared_key")
	}

	random, err := newNumericRandom(8)
	if err != nil {
		return "", "", err
	}

	sum := md5.Sum([]byte(sharedKey + random))
	md5hex := fmt.Sprintf("%x", sum[:])

	return random, md5hex, nil
}

func acHTTPError(resp *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("ac api %s %s status=%d read_body_failed=%v", resp.Request.Method, resp.Request.URL.String(), resp.StatusCode, err)
	}

	text := strings.TrimSpace(string(body))
	if text == "" {
		return fmt.Errorf("ac api %s %s status=%d", resp.Request.Method, resp.Request.URL.String(), resp.StatusCode)
	}
	return fmt.Errorf("ac api %s %s status=%d body=%s", resp.Request.Method, resp.Request.URL.String(), resp.StatusCode, text)
}

func newNumericRandom(digits int) (string, error) {
	if digits <= 0 {
		digits = 16
	}

	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	s := n.String()
	if len(s) < digits {
		s = strings.Repeat("0", digits-len(s)) + s
	}
	return s, nil
}
