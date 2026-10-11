package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

var (
	_ TargetDocumenter = (*eksProvider)(nil)
	_ TargetDocumenter = (*gkeProvider)(nil)
	_ TargetDocumenter = (*aksProvider)(nil)
)

// The answers to a managed connector's block that does not decode, each naming the block http_request takes.
var (
	errEKSBlock = errors.New(`eks_auth must be a JSON object, as in http_request: {"cluster_name":"<name>"}, plus ` +
		`"region" when the cluster is outside the configured region`)
	errGKEBlock = errors.New(`gke_auth must be a JSON object, as in http_request: {"project":"<project>",` +
		`"location":"<location>","cluster_name":"<name>"}`)
	errAKSBlock = errors.New(`aks_auth must be a JSON object, as in http_request: {"subscription_id":"<id>",` +
		`"resource_group":"<group>","cluster_name":"<name>"}`)
)

var (
	// errNoClusterHost refuses a resolved endpoint with no host, which hostFromEndpoint returns for one that does
	// not parse.
	errNoClusterHost = errors.New("the cluster's endpoint names no host")
	// errIPv6ClusterHost refuses an IPv6 control-plane address: the managed gates' own ClusterRole fetch builds
	// "https://" + host unbracketed, so the endpoint a lookup published would not parse either.
	errIPv6ClusterHost = errors.New("the cluster's endpoint is an IPv6 address, which targeted lookups do not support")
)

// PrepareLookup validates an eks lookup with no I/O; Resolve runs the cached DescribeCluster the host gate pins.
func (p *eksProvider) PrepareLookup(q apiref.Query, raw json.RawMessage) (TargetLookup, error) {
	return prepareKubeLookup(
		&p.k8sGate,
		q,
		raw,
		errEKSBlock,
		func(ctx context.Context, a *EKSAuthArgs) (Target, error) {
			return resolveManaged(ctx, &p.k8sGate, a, p.resolveHost)
		},
	)
}

// PrepareLookup validates a gke lookup with no I/O; Resolve runs the cached clusters.get the host gate pins.
func (p *gkeProvider) PrepareLookup(q apiref.Query, raw json.RawMessage) (TargetLookup, error) {
	return prepareKubeLookup(
		&p.k8sGate,
		q,
		raw,
		errGKEBlock,
		func(ctx context.Context, a *GKEAuthArgs) (Target, error) {
			return resolveManaged(ctx, &p.k8sGate, a, p.resolveHost)
		},
	)
}

// PrepareLookup validates an aks lookup with no I/O; Resolve runs the cached ListClusterUserCredentials the host
// gate pins.
func (p *aksProvider) PrepareLookup(q apiref.Query, raw json.RawMessage) (TargetLookup, error) {
	return prepareKubeLookup(
		&p.k8sGate,
		q,
		raw,
		errAKSBlock,
		func(ctx context.Context, a *AKSAuthArgs) (Target, error) {
			return resolveManaged(ctx, &p.k8sGate, a, p.resolveHost)
		},
	)
}

// resolveManaged resolves a managed cluster's host through resolveHost, the same cached resolution the connector's
// host gate pins, and publishes it with no port: the managed gates pin 443, which an omitted port means, and an
// explicit one would make the template differ from the URL a model's hop 2 sends. It refuses a host it could not
// publish as the gates admit it.
func resolveManaged[A any](
	ctx context.Context, g *k8sGate[A], args *A, resolveHost func(context.Context, *A) (string, error),
) (Target, error) {
	host, err := resolveHost(ctx, args)
	if err != nil {
		return Target{}, err
	}
	if host == "" {
		return Target{}, errNoClusterHost
	}
	if err = AdmitHost(host); err != nil {
		return Target{}, fmt.Errorf("%s: the cluster's endpoint: %w", g.connector, err)
	}
	if strings.Contains(host, ":") {
		return Target{}, errIPv6ClusterHost
	}

	return Target{Endpoint: "https://" + host, Identity: g.target(args) + "@" + host}, nil
}
