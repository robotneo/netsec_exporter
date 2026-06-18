package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"netsec_exporter/core"
)

var ErrAuthExpired = errors.New("qianxin auth expired")

type Session struct {
	Username string
	Token    string
	Cookie   string
}

func NewTokenSession(username, token string) Session {
	username = strings.TrimSpace(username)
	token = strings.TrimSpace(token)
	if token == "" && username == "" {
		return Session{}
	}
	return Session{
		Username: username,
		Token:    token,
		Cookie:   fmt.Sprintf("token=%s", token),
	}
}

func (c *Client) Login(dev core.Device) (Session, error) {
	if strings.TrimSpace(dev.Username) == "" || strings.TrimSpace(dev.Password) == "" {
		return Session{}, fmt.Errorf("missing username/password")
	}

	baseURL, err := normalizeBaseURL(dev.Host)
	if err != nil {
		return Session{}, err
	}

	body, err := json.Marshal(map[string]string{
		"username": dev.Username,
		"password": dev.Password,
	})
	if err != nil {
		return Session{}, err
	}

	loginPaths := []string{"/v1.0/login", "/v1.0/login/"}
	var lastErr error
	for _, path := range loginPaths {
		sess, err := c.loginOnce(context.Background(), buildURL(baseURL, path), body)
		if err == nil {
			return sess, nil
		}
		lastErr = err
	}
	return Session{}, lastErr
}

func (c *Client) loginOnce(ctx context.Context, url string, body []byte) (Session, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return Session{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Session{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return Session{}, fmt.Errorf("login returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	var r struct {
		Success   *bool  `json:"success"`
		ErrorCode string `json:"error_code"`
		Result    struct {
			Username  string `json:"username"`
			Token     string `json:"token"`
			ErrorCode string `json:"error_code"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Session{}, err
	}

	if r.Success != nil && !*r.Success {
		return Session{}, fmt.Errorf("login failed")
	}

	code := strings.TrimSpace(r.Result.ErrorCode)
	if code == "" {
		code = strings.TrimSpace(r.ErrorCode)
	}
	if code != "" && code != "0" && strings.ToLower(code) != "success" {
		return Session{}, fmt.Errorf("login failed: error_code=%s", code)
	}

	token := strings.TrimSpace(r.Result.Token)
	if token == "" {
		return Session{}, fmt.Errorf("login failed: empty token")
	}

	cookieParts := []string{}
	seen := map[string]struct{}{}
	addCookie := func(name, value string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := name + "=" + value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		cookieParts = append(cookieParts, key)
	}

	addCookie("token", token)
	for _, ck := range resp.Cookies() {
		addCookie(ck.Name, ck.Value)
	}

	return Session{
		Username: strings.TrimSpace(r.Result.Username),
		Token:    token,
		Cookie:   strings.Join(cookieParts, "; "),
	}, nil
}

func EnsureRESTOK(function string, head RESTResponseHead) error {
	if head.ErrorCode != 0 {
		msg := strings.TrimSpace(head.ErrorString)
		if head.ErrorCode == 401 || head.ErrorCode == 403 ||
			strings.Contains(msg, "未登录") || strings.Contains(msg, "会话") ||
			strings.Contains(msg, "失效") || strings.Contains(msg, "过期") ||
			strings.Contains(msg, "认证") || strings.Contains(msg, "登录") ||
			strings.Contains(strings.ToLower(msg), "token") {
			return ErrAuthExpired
		}
		return fmt.Errorf("%s failed: error_code=%d error_string=%s", function, head.ErrorCode, head.ErrorString)
	}
	return nil
}
