package client

import (
	"net/http"
	"time"
)

type Client struct {
	HTTPClient *http.Client
}

func New(timeout time.Duration, insecureSkipVerify bool) *Client {
	return &Client{
		HTTPClient: NewHTTPClient(timeout, insecureSkipVerify, true),
	}
}
