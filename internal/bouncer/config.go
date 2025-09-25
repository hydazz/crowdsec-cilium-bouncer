package bouncer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hydazz/crowdsec-cilium-bouncer/internal/crowdsec"
)

// Config captures runtime configuration for the bouncer process.
type Config struct {
	CrowdSecURL         string
	CrowdSecAPIKey      string
	CrowdSecTimeout     time.Duration
	CrowdSecInsecureTLS bool
	SyncInterval        time.Duration
	Filters             crowdsec.DecisionFilters
	PolicyName          string
	PolicyLabels        map[string]string
	EndpointSelector    map[string]string
	DenyIngress         bool
	DenyEgress          bool
}

// LoadConfigFromEnv builds a Config from environment variables.
func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		CrowdSecTimeout: 10 * time.Second,
		SyncInterval:    30 * time.Second,
		PolicyName:      "crowdsec-cilium-bouncer",
		PolicyLabels: map[string]string{
			"app.kubernetes.io/name":       "crowdsec-cilium-bouncer",
			"app.kubernetes.io/managed-by": "crowdsec-cilium-bouncer",
		},
		EndpointSelector: map[string]string{},
		DenyIngress:      true,
		DenyEgress:       true,
	}

	var missing []string

	cfg.CrowdSecURL = strings.TrimSpace(os.Getenv("CROWDSEC_URL"))
	if cfg.CrowdSecURL == "" {
		missing = append(missing, "CROWDSEC_URL")
	}

	cfg.CrowdSecAPIKey = strings.TrimSpace(os.Getenv("CROWDSEC_BOUNCER_API_KEY"))
	if cfg.CrowdSecAPIKey == "" {
		missing = append(missing, "CROWDSEC_BOUNCER_API_KEY")
	}

	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	if value := strings.TrimSpace(os.Getenv("CROWDSEC_TIMEOUT")); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid CROWDSEC_TIMEOUT: %w", err)
		}
		if duration <= 0 {
			return cfg, fmt.Errorf("CROWDSEC_TIMEOUT must be positive")
		}
		cfg.CrowdSecTimeout = duration
	}

	if value := strings.TrimSpace(os.Getenv("CROWDSEC_INSECURE_SKIP_VERIFY")); value != "" {
		insecure, err := strconv.ParseBool(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid CROWDSEC_INSECURE_SKIP_VERIFY: %w", err)
		}
		cfg.CrowdSecInsecureTLS = insecure
	}

	if value := strings.TrimSpace(os.Getenv("SYNC_INTERVAL")); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid SYNC_INTERVAL: %w", err)
		}
		if duration <= 0 {
			return cfg, fmt.Errorf("SYNC_INTERVAL must be positive")
		}
		cfg.SyncInterval = duration
	}

	if value := strings.TrimSpace(os.Getenv("CROWDSEC_FILTER_SCOPES")); value != "" {
		cfg.Filters.Scopes = splitCSV(value)
	}

	if value := strings.TrimSpace(os.Getenv("CROWDSEC_FILTER_TYPES")); value != "" {
		cfg.Filters.Types = splitCSV(value)
	}

	if value := strings.TrimSpace(os.Getenv("CILIUM_POLICY_NAME")); value != "" {
		cfg.PolicyName = value
	}

	if value := strings.TrimSpace(os.Getenv("CILIUM_POLICY_LABELS")); value != "" {
		labels, err := parseKeyValuePairs(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid CILIUM_POLICY_LABELS: %w", err)
		}
		for key, val := range labels {
			cfg.PolicyLabels[key] = val
		}
	}

	if value := strings.TrimSpace(os.Getenv("CILIUM_ENDPOINT_SELECTOR")); value != "" {
		labels, err := parseKeyValuePairs(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid CILIUM_ENDPOINT_SELECTOR: %w", err)
		}
		cfg.EndpointSelector = labels
	}

	if value := strings.TrimSpace(os.Getenv("CILIUM_DENY_INGRESS")); value != "" {
		deny, err := strconv.ParseBool(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid CILIUM_DENY_INGRESS: %w", err)
		}
		cfg.DenyIngress = deny
	}

	if value := strings.TrimSpace(os.Getenv("CILIUM_DENY_EGRESS")); value != "" {
		deny, err := strconv.ParseBool(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid CILIUM_DENY_EGRESS: %w", err)
		}
		cfg.DenyEgress = deny
	}

	return cfg, nil
}

func splitCSV(input string) []string {
	tokens := strings.Split(input, ",")
	values := make([]string, 0, len(tokens))
	for _, token := range tokens {
		trimmed := strings.TrimSpace(token)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func parseKeyValuePairs(input string) (map[string]string, error) {
	result := make(map[string]string)
	for _, entry := range strings.Split(input, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("expected key=value but got %q", entry)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("empty key in %q", entry)
		}

		result[key] = value
	}
	return result, nil
}
