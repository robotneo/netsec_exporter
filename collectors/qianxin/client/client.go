package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netsec_exporter/core"
)

type RESTRequest struct {
	Head RESTHead `json:"head"`
	Body RESTBody `json:"body"`
}

type RESTHead struct {
	Function  string `json:"function"`
	Module    string `json:"module"`
	PageIndex int    `json:"page_index"`
	PageSize  int    `json:"page_size"`
}

type RESTBody struct {
	Data map[string]any `json:"data"`
}

type RESTResponseHead struct {
	ErrorCode   int    `json:"error_code"`
	ErrorString string `json:"error_string"`
}

type Client struct {
	HTTPClient *http.Client
}

func New(timeout time.Duration, insecureSkipVerify bool) *Client {
	transport := &http.Transport{}
	if insecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		HTTPClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
}

func normalizeBaseURL(host string) (string, error) {
	baseURL := strings.TrimSpace(host)
	if baseURL == "" {
		return "", fmt.Errorf("missing host")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	return strings.TrimRight(baseURL, "/"), nil
}

func buildURL(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if path == "" {
		return baseURL
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

func applySession(req *http.Request, sess Session) {
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(sess.Username) != "" {
		req.Header.Set("username", strings.TrimSpace(sess.Username))
	}
	if strings.TrimSpace(sess.Cookie) != "" {
		req.Header.Set("Cookie", sess.Cookie)
	}
	if strings.TrimSpace(sess.Token) != "" {
		req.Header.Set("token", sess.Token)
	}
}

func (c *Client) NewRequest(ctx context.Context, dev core.Device, sess Session, method, path string, body io.Reader) (*http.Request, error) {
	baseURL, err := normalizeBaseURL(dev.Host)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, buildURL(baseURL, path), body)
	if err != nil {
		return nil, err
	}
	applySession(req, sess)
	return req, nil
}

func (c *Client) DoJSON(ctx context.Context, dev core.Device, sess Session, method, path string, reqBody any, out any) error {
	var body io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := c.NewRequest(ctx, dev, sess, method, path, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return ErrAuthExpired
		}
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) PostREST(ctx context.Context, dev core.Device, sess Session, reqBody any, out any) error {
	err := c.DoJSON(ctx, dev, sess, "POST", "/v1.0/rest/", reqBody, out)
	if err != nil {
		err = c.DoJSON(ctx, dev, sess, "POST", "/v1.0/rest", reqBody, out)
		if err != nil {
			return err
		}
	}
	return nil
}
