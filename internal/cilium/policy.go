package cilium

import (
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	clusterwidePolicyGVK = schema.GroupVersionKind{
		Group:   "cilium.io",
		Version: "v2",
		Kind:    "CiliumClusterwideNetworkPolicy",
	}
)

// BuildClusterwidePolicy renders a CiliumClusterwideNetworkPolicy that denies traffic originating from the provided CIDRs.
func BuildClusterwidePolicy(name string, labels map[string]string, endpointSelector map[string]string, cidrs []string, denyIngress, denyEgress bool) *unstructured.Unstructured {
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(clusterwidePolicyGVK)
	policy.SetName(name)

	if len(labels) > 0 {
		policy.SetLabels(labels)
	}

	selector := map[string]interface{}{}
	if len(endpointSelector) > 0 {
		selector["matchLabels"] = endpointSelector
	} else {
		selector["matchLabels"] = map[string]string{}
	}

	// ensure deterministic order for idempotent updates.
	sorted := append([]string(nil), cidrs...)
	sort.Strings(sorted)

	spec := map[string]interface{}{
		"endpointSelector": selector,
	}

	if denyIngress {
		spec["ingressDeny"] = []interface{}{buildCIDRSet("fromCIDRSet", sorted)}
	}

	if denyEgress {
		spec["egressDeny"] = []interface{}{buildCIDRSet("toCIDRSet", sorted)}
	}

	policy.Object["spec"] = spec

	return policy
}

func buildCIDRSet(key string, cidrs []string) map[string]interface{} {
	entries := make([]interface{}, 0, len(cidrs))
	for _, cidr := range cidrs {
		entries = append(entries, map[string]interface{}{"cidr": cidr})
	}

	return map[string]interface{}{key: entries}
}
