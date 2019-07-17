package auth

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"net/http"
	"time"
)

var client = &withMetrics{&http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 1 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 1 * time.Second,
	},
}}

type withMetrics struct {
	*http.Client
}

func (c *withMetrics) do(r *http.Request, metrics prometheus.ObserverVec) (*http.Response, error) {
	start := time.Now()
	response, err := c.Client.Do(r)
	if err == nil && metrics != nil {
		metrics.
			With(prometheus.Labels{"code": fmt.Sprintf("%v", response.StatusCode)}).
			Observe(time.Since(start).Seconds())
	}
	return response, err
}
