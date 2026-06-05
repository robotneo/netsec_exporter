package client

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"time"
)

func NewHTTPClient(timeout time.Duration, insecureSkipVerify bool, enableCookieJar bool) *http.Client {
	var jar http.CookieJar
	if enableCookieJar {
		jar, _ = cookiejar.New(nil)
	}

	transport := &http.Transport{}
	if insecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		Jar:       jar,
	}
}
