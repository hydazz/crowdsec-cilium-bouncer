package crowdsec

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config captures the information required to talk to the CrowdSec Local API.
type Config struct {
	URL                string
	APIKey             string
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// DecisionFilters limits which decisions are retrieved from CrowdSec.
type DecisionFilters struct {
	Scopes []string
	Types  []string
}

// Decision represents a single CrowdSec security decision.
type Decision struct {
	ID        int64
	Scope     string
	Type      string
	Value     string
	Duration  string
	ExpiresAt *time.Time
}

// Client implements the small portion of the CrowdSec LAPI that we consume.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	headers    http.Header
}

// NewClient instantiates a new CrowdSec client using the provided configuration.
func NewClient(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("crowdsec url cannot be empty")
	}

	if cfg.APIKey == "" {
		return nil, errors.New("crowdsec api key cannot be empty")
	}

	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid crowdsec url: %w", err)
	}

	if parsed.Scheme == "" {
		parsed.Scheme = "http"
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	transport.MaxIdleConns = 1
	transport.MaxIdleConnsPerHost = 1
	transport.IdleConnTimeout = 30 * time.Second
	if parsed.Scheme == "https" && cfg.InsecureSkipVerify {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}

		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	client := &http.Client{Timeout: cfg.Timeout}
	client.Transport = transport

	headers := make(http.Header)
	headers.Set("User-Agent", "crowdsec-cilium-bouncer/1.0")
	headers.Set("X-Api-Key", cfg.APIKey)

	return &Client{
		baseURL:    parsed,
		httpClient: client,
		headers:    headers,
	}, nil
}

// FetchDecisions returns the current decisions that match the provided filters.
func (c *Client) FetchDecisions(ctx context.Context, filters DecisionFilters) ([]Decision, error) {
	endpoint, err := c.resolve("/v1/decisions")
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	for _, scope := range filters.Scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed != "" {
			query.Add("scope", trimmed)
		}
	}

	for _, decisionType := range filters.Types {
		trimmed := strings.TrimSpace(decisionType)
		if trimmed != "" {
			query.Add("type", trimmed)
		}
	}

	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header = c.headers.Clone()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query decisions: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crowdsec returned %s", resp.Status)
	}

	var payload []apiDecision
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode decisions: %w", err)
	}

	decisions := make([]Decision, 0, len(payload))
	for _, item := range payload {
		decisions = append(decisions, item.toDecision())
	}

	return decisions, nil
}

func (c *Client) resolve(path string) (*url.URL, error) {
	resolved, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("resolve crowdsec path: %w", err)
	}

	return resolved, nil
}

type apiDecision struct {
	ID         int64      `json:"id"`
	Scope      string     `json:"scope"`
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	Duration   string     `json:"duration"`
	Until      *time.Time `json:"until"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Expiration *time.Time `json:"expiration"`
}

func (a apiDecision) toDecision() Decision {
	expires := a.Until
	if expires == nil {
		expires = a.ExpiresAt
	}
	if expires == nil {
		expires = a.Expiration
	}

	return Decision{
		ID:        a.ID,
		Scope:     a.Scope,
		Type:      a.Type,
		Value:     a.Value,
		Duration:  a.Duration,
		ExpiresAt: expires,
	}
}
