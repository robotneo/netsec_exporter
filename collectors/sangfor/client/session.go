package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"netsec_exporter/core"
)

type Session struct {
	Token     string
	Namespace string
	LoginAt   time.Time
}

type SessionManager struct {
	client *Client

	mu       sync.Mutex
	sessions map[string]Session

	ttl time.Duration
}

func NewSessionManager(client *Client, ttl time.Duration) *SessionManager {
	return &SessionManager{
		client:   client,
		sessions: make(map[string]Session),
		ttl:      ttl,
	}
}

func (m *SessionManager) Invalidate(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, host)
}

func (m *SessionManager) GetOrLogin(dev core.Device) (Session, error) {
	m.mu.Lock()
	s, ok := m.sessions[dev.Host]
	if ok && s.Token != "" && s.Namespace != "" && time.Since(s.LoginAt) < m.ttl {
		m.mu.Unlock()
		return s, nil
	}
	m.mu.Unlock()

	if dev.Username == "" || dev.Password == "" {
		return Session{}, fmt.Errorf("missing username/password for device %s", dev.Name)
	}

	baseURL := fmt.Sprintf("https://%s", dev.Host)
	loginURL := fmt.Sprintf("%s/api/v1/namespaces/@namespace/login", baseURL)

	bodyBytes, err := json.Marshal(map[string]string{
		"name":     dev.Username,
		"password": dev.Password,
	})
	if err != nil {
		return Session{}, err
	}

	req, err := http.NewRequest("POST", loginURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return Session{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.HTTPClient.Do(req)
	if err != nil {
		return Session{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Session{}, fmt.Errorf("login api status code: %d", resp.StatusCode)
	}

	var lr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Namespace   string `json:"namespace"`
			LoginResult struct {
				Token string `json:"token"`
			} `json:"loginResult"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return Session{}, err
	}
	if lr.Code != 0 {
		return Session{}, fmt.Errorf("login failed: code=%d message=%s", lr.Code, lr.Message)
	}
	if lr.Data.LoginResult.Token == "" || lr.Data.Namespace == "" {
		return Session{}, fmt.Errorf("login response missing token/namespace")
	}

	sess := Session{
		Token:     lr.Data.LoginResult.Token,
		Namespace: lr.Data.Namespace,
		LoginAt:   time.Now(),
	}

	if m.client.HTTPClient.Jar != nil {
		u, err := url.Parse(baseURL)
		if err == nil {
			m.client.HTTPClient.Jar.SetCookies(u, []*http.Cookie{
				{Name: "token", Value: sess.Token, Path: "/"},
			})
		}
	}

	m.mu.Lock()
	m.sessions[dev.Host] = sess
	m.mu.Unlock()

	return sess, nil
}

