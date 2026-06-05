package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HCISession struct {
	Token     string
	Cookie    string
	ExpiresAt time.Time
	LoginAt   time.Time
}

type HCISessionManager struct {
	client *HCIClient

	mu       sync.Mutex
	sessions map[string]HCISession
}

func NewHCISessionManager(client *HCIClient) *HCISessionManager {
	return &HCISessionManager{
		client:   client,
		sessions: map[string]HCISession{},
	}
}

func (m *HCISessionManager) Invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = map[string]HCISession{}
}

func (m *HCISessionManager) GetOrLogin(ctx context.Context, username string, password string) (HCISession, error) {
	cacheKey := m.client.BaseURL + "|" + username

	m.mu.Lock()
	s, ok := m.sessions[cacheKey]
	if ok && s.Token != "" && time.Until(s.ExpiresAt) > 2*time.Minute {
		m.mu.Unlock()
		return s, nil
	}
	m.mu.Unlock()

	s, err := m.client.LoginWithPassword(ctx, username, password)
	if err != nil {
		return HCISession{}, err
	}

	m.mu.Lock()
	m.sessions[cacheKey] = s
	m.mu.Unlock()
	return s, nil
}

func (c *HCIClient) LoginWithPassword(ctx context.Context, username string, password string) (HCISession, error) {
	modulus, err := c.GetPublicKeyModulus(ctx)
	if err != nil {
		return HCISession{}, err
	}

	encrypted, err := encryptPasswordWithModulus(password, modulus)
	if err != nil {
		return HCISession{}, err
	}

	cookieVal, err := randomHex(16)
	if err != nil {
		return HCISession{}, err
	}

	body := map[string]any{
		"auth": map[string]any{
			"passwordCredentials": map[string]any{
				"username": username,
				"password": encrypted,
			},
		},
	}

	b, err := json.Marshal(body)
	if err != nil {
		return HCISession{}, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/janus/authenticate", bytes.NewReader(b))
	if err != nil {
		return HCISession{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "aCMPAuthToken="+cookieVal)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return HCISession{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return HCISession{}, fmt.Errorf("authenticate status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var ar struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
		Data    struct {
			Access struct {
				Token struct {
					IssuedAt string `json:"issued_at"`
					Expires  string `json:"expires"`
					ID       string `json:"id"`
				} `json:"token"`
			} `json:"access"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return HCISession{}, err
	}
	if ar.Code != 0 {
		return HCISession{}, fmt.Errorf("authenticate failed: code=%d message=%s", ar.Code, ar.Message)
	}
	if strings.TrimSpace(ar.Data.Access.Token.ID) == "" {
		return HCISession{}, fmt.Errorf("authenticate missing token id")
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if strings.TrimSpace(ar.Data.Access.Token.Expires) != "" {
		if t, parseErr := time.Parse(time.RFC3339Nano, ar.Data.Access.Token.Expires); parseErr == nil {
			expiresAt = t
		}
	}

	return HCISession{
		Token:     ar.Data.Access.Token.ID,
		Cookie:    cookieVal,
		ExpiresAt: expiresAt,
		LoginAt:   time.Now(),
	}, nil
}

func encryptPasswordWithModulus(password string, modulusHex string) (string, error) {
	modulusHex = normalizeHexString(modulusHex)
	if modulusHex == "" {
		return "", fmt.Errorf("empty modulus")
	}

	n := new(big.Int)
	if _, ok := n.SetString(modulusHex, 16); !ok {
		return "", fmt.Errorf("invalid modulus")
	}

	pub := &rsa.PublicKey{N: n, E: 65537}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(password))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

func normalizeHexString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func randomHex(n int) (string, error) {
	if n <= 0 {
		n = 16
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
