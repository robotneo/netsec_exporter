package client

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"time"
)

type Client struct {
	HTTPClient *http.Client
}

func New(timeout time.Duration, insecureSkipVerify bool) *Client {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{}
	if insecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		HTTPClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			Jar:       jar,
		},
	}
}

