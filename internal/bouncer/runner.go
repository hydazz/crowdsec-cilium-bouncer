package bouncer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/hydazz/crowdsec-cilium-bouncer/internal/cilium"
	"github.com/hydazz/crowdsec-cilium-bouncer/internal/crowdsec"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const policyHashAnnotation = "crowdsec.cilium-bouncer/hash"

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
		"policy", r.cfg.PolicyName,
		"denyIngress", r.cfg.DenyIngress,
		"allowLocalCidrs", r.cfg.AllowLocalCIDRs,
	)

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
	start := r.now()

    decisions, err := r.fetchDecisions(ctx)
	if err != nil {
		return fmt.Errorf("fetch decisions: %w", err)
	}

	r.log.Debug("fetched decisions", "count", len(decisions))

	cidrs, stats := renderCIDRs(r.now(), decisions, r.cfg.AllowLocalCIDRs)

	if !r.cfg.AllowLocalCIDRs && stats.SkippedLocal > 0 {
		r.log.Debug("skipped local CIDRs", "count", stats.SkippedLocal)
	}
	if stats.SkippedInvalid > 0 || stats.SkippedExpired > 0 {
		r.log.Debug("filtered decisions",
			"expired", stats.SkippedExpired,
			"invalid", stats.SkippedInvalid,
		)
	}

	policy := cilium.BuildClusterwidePolicy(
		r.cfg.PolicyName,
		r.cfg.PolicyLabels,
		r.cfg.EndpointSelector,
		cidrs,
		r.cfg.DenyIngress,
		false,
	)

	annotations := policy.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[policyHashAnnotation] = hashCIDRs(cidrs)
	policy.SetAnnotations(annotations)

	updated, err := applyPolicy(ctx, r.client, policy)
	if err != nil {
		return fmt.Errorf("apply cilium policy: %w", err)
	}

	duration := r.now().Sub(start)
	if updated {
		r.log.Info("synced crowdsec decisions",
			"decisions", len(decisions),
			"cidrs", len(cidrs),
			"skippedLocal", stats.SkippedLocal,
			"skippedExpired", stats.SkippedExpired,
			"skippedInvalid", stats.SkippedInvalid,
			"duration", duration.String(),
		)
	} else {
		r.log.Debug("policy already up to date",
			"decisions", len(decisions),
			"cidrs", len(cidrs),
			"duration", duration.String(),
		)
	}

	return nil
}

func applyPolicy(ctx context.Context, kubeClient client.Client, policy *unstructured.Unstructured) (bool, error) {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(policy.GroupVersionKind())
	existing.SetName(policy.GetName())

	if err := kubeClient.Get(ctx, client.ObjectKey{Name: policy.GetName()}, existing); err != nil {
		if apierrors.IsNotFound(err) {
			if err := kubeClient.Create(ctx, policy); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, err
	}

	if annotationsEqual(existing.GetAnnotations(), policy.GetAnnotations()) &&
		equality.Semantic.DeepEqual(existing.GetLabels(), policy.GetLabels()) &&
		equality.Semantic.DeepEqual(existing.Object["spec"], policy.Object["spec"]) {
		return false, nil
	}

	policy.SetResourceVersion(existing.GetResourceVersion())
	if err := kubeClient.Update(ctx, policy); err != nil {
		return false, err
	}

	return true, nil
}

func renderCIDRs(now time.Time, decisions []crowdsec.Decision, allowLocal bool) ([]string, renderStats) {
	entries := sets.New[string]()
	stats := renderStats{}

	for _, decision := range decisions {
		if decision.ExpiresAt != nil && now.After(*decision.ExpiresAt) {
			stats.SkippedExpired++
			continue
		}

		switch strings.ToLower(decision.Scope) {
		case "ip":
			cidr, ok := ensureIPCIDR(decision.Value)
			if !ok {
				stats.SkippedInvalid++
				continue
			}
			if !allowLocal && isLocalCIDR(cidr) {
				stats.SkippedLocal++
				continue
			}
			entries.Insert(cidr)
		case "range":
			_, network, err := net.ParseCIDR(decision.Value)
			if err != nil || network == nil {
				stats.SkippedInvalid++
				continue
			}
			cidr := network.String()
			if !allowLocal && isLocalCIDR(cidr) {
				stats.SkippedLocal++
				continue
			}
			entries.Insert(cidr)
		default:
			stats.SkippedInvalid++
		}
	}

	list := sets.List(entries)
	sort.Strings(list)
	return list, stats
}

func ensureIPCIDR(value string) (string, bool) {
	if value == "" {
		return "", false
	}

	if strings.Contains(value, "/") {
		if _, network, err := net.ParseCIDR(value); err == nil && network != nil {
			return network.String(), true
		}
		return "", false
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return "", false
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return fmt.Sprintf("%s/32", ipv4.String()), true
	}

	return fmt.Sprintf("%s/128", ip.String()), true
}

func isLocalCIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network == nil {
		return false
	}

	ip := network.IP
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	return ip.IsPrivate()
}

func hashCIDRs(cidrs []string) string {
	if len(cidrs) == 0 {
		return ""
	}

	h := sha256.New()
	for _, cidr := range cidrs {
		_, _ = h.Write([]byte(cidr))
		_, _ = h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func annotationsEqual(a, b map[string]string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	if len(a) != len(b) {
		return false
	}

	for key, val := range a {
		if b[key] != val {
			return false
		}
	}

	return true
}

type renderStats struct {
	SkippedExpired int
	SkippedInvalid int
	SkippedLocal   int
}
