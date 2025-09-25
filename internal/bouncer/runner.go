package bouncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hydazz/crowdsec-cilium-bouncer/internal/cilium"
	"github.com/hydazz/crowdsec-cilium-bouncer/internal/crowdsec"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Runner periodically synchronises CrowdSec decisions into a Cilium policy.
type Runner struct {
	cfg    Config
	client client.Client
	log    *slog.Logger
	crowd  *crowdsec.Client
	now    func() time.Time
}

// NewRunner constructs a Runner ready for execution.
func NewRunner(cfg Config, kubeClient client.Client, logger *slog.Logger) (*Runner, error) {
	if kubeClient == nil {
		return nil, errors.New("kubernetes client cannot be nil")
	}

	crowdClient, err := crowdsec.NewClient(crowdsec.Config{
		URL:                cfg.CrowdSecURL,
		APIKey:             cfg.CrowdSecAPIKey,
		Timeout:            cfg.CrowdSecTimeout,
		InsecureSkipVerify: cfg.CrowdSecInsecureTLS,
	})
	if err != nil {
		return nil, fmt.Errorf("create crowdsec client: %w", err)
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Runner{
		cfg:    cfg,
		client: kubeClient,
		log:    logger,
		crowd:  crowdClient,
		now:    time.Now,
	}, nil
}

// Run starts the synchronisation loop until the context is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.cfg.SyncInterval)
	defer ticker.Stop()

	r.log.Info("starting crowdsec cilium bouncer",
		"syncInterval", r.cfg.SyncInterval.String(),
		"policy", r.cfg.PolicyName)

	if err := r.syncOnce(ctx); err != nil {
		r.log.Error("initial sync failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			r.log.Info("shutting down")
			return ctx.Err()
		case <-ticker.C:
			if err := r.syncOnce(ctx); err != nil {
				r.log.Error("sync failed", "error", err)
			}
		}
	}
}

func (r *Runner) syncOnce(ctx context.Context) error {
	decisions, err := r.crowd.FetchDecisions(ctx, r.cfg.Filters)
	if err != nil {
		return fmt.Errorf("fetch decisions: %w", err)
	}

	cidrs := renderCIDRs(r.now(), decisions)

	policy := cilium.BuildClusterwidePolicy(
		r.cfg.PolicyName,
		r.cfg.PolicyLabels,
		r.cfg.EndpointSelector,
		cidrs,
		r.cfg.DenyIngress,
		r.cfg.DenyEgress,
	)

	if err := applyPolicy(ctx, r.client, policy); err != nil {
		return fmt.Errorf("apply cilium policy: %w", err)
	}

	r.log.Info("applied crowdsec decisions", "decisionCount", len(decisions), "cidrCount", len(cidrs))
	return nil
}

func applyPolicy(ctx context.Context, kubeClient client.Client, policy *unstructured.Unstructured) error {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(policy.GroupVersionKind())
	existing.SetName(policy.GetName())

	if err := kubeClient.Get(ctx, client.ObjectKey{Name: policy.GetName()}, existing); err != nil {
		if apierrors.IsNotFound(err) {
			return kubeClient.Create(ctx, policy)
		}
		return err
	}

	policy.SetResourceVersion(existing.GetResourceVersion())
	return kubeClient.Update(ctx, policy)
}

func renderCIDRs(now time.Time, decisions []crowdsec.Decision) []string {
	entries := sets.New[string]()

	for _, decision := range decisions {
		if decision.ExpiresAt != nil && now.After(*decision.ExpiresAt) {
			continue
		}

		switch strings.ToLower(decision.Scope) {
		case "ip":
			if cidr := ensureIPCIDR(decision.Value); cidr != "" {
				entries.Insert(cidr)
			}
		case "range":
			if _, _, err := net.ParseCIDR(decision.Value); err == nil {
				entries.Insert(decision.Value)
			}
		}
	}

	return sets.List(entries)
}

func ensureIPCIDR(value string) string {
	if value == "" {
		return ""
	}

	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err == nil {
			return value
		}
		return ""
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}

	if ip.To4() != nil {
		return fmt.Sprintf("%s/32", ip.String())
	}

	return fmt.Sprintf("%s/128", ip.String())
}
