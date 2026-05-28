package client

import (
	"crypto/tls"
	"net/http"
	"time"
)

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

