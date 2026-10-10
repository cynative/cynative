package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

const (
	bootEKSCluster = "c1"
	bootSub        = "00000000-1111-2222-3333-444444444444"
)

// bootCall is one call a fakeObserver was told about.
type bootCall struct {
	connector, call, target string
	ended                   bool
	err                     error
}

// fakeObserver records every call it is told about. refuse makes Begin fail; ended, when set, receives a value
// each time a call ends.
type fakeObserver struct {
	mu     sync.Mutex
	calls  []bootCall
	refuse error
	ended  chan struct{}
}

func (o *fakeObserver) Begin(connector, call, target string) (func(error), error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.refuse != nil {
		return nil, o.refuse
	}
	i := len(o.calls)
	o.calls = append(o.calls, bootCall{connector: connector, call: call, target: target})

	return func(err error) {
		o.mu.Lock()
		o.calls[i].ended, o.calls[i].err = true, err
		o.mu.Unlock()
		if o.ended != nil {
			o.ended <- struct{}{}
		}
	}, nil
}

func (o *fakeObserver) snapshot() []bootCall {
	o.mu.Lock()
	defer o.mu.Unlock()

	return slices.Clone(o.calls)
}

// observed is ctx carrying a fresh observer.
func observed(ctx context.Context) (context.Context, *fakeObserver) {
	o := &fakeObserver{}

	return WithBootstrapObserver(ctx, o), o
}

// countingEKS is an eks provider in us-east-1 whose DescribeCluster is fake, counted, and answers with err.
func countingEKS(n *atomic.Int64, err error) *eksProvider {
	p := newEKSProvider(aws.Config{Region: "us-east-1"})
	p.describeCluster = func(context.Context, aws.Config, string) (clusterTLS, error) {
		n.Add(1)

		return clusterTLS{host: "abc.gr7.us-east-1.eks.amazonaws.com", caData: "Y2E="}, err
	}

	return p
}

// aksKubeconfigServer answers ListClusterUserCredentials with a token kubeconfig and counts the calls.
func aksKubeconfigServer(t *testing.T, n *atomic.Int64) *aksProvider {
	t.Helper()
	kubeconfig := base64.StdEncoding.EncodeToString([]byte(fakeKubeconfigToken()))
	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterUser","value":"%s"}]}`, kubeconfig)
	})
	p := newAKSProvider(mockCredential(azcore.AccessToken{}, nil), cloud.Configuration{})
	p.newClient = aksClientFor(srv.URL, srv.Client())

	return p
}

// TestObserveBootstrap_ReportsEachResolutionOnce pins, for each managed connector, that the call which starts a
// cluster's resolution is reported before it runs and ended after, with the connector, the vendor call and the
// cluster target, and that a later resolution served from the cache reports nothing.
func TestObserveBootstrap_ReportsEachResolutionOnce(t *testing.T) {
	t.Parallel()
	var eksCalls, gkeCalls, aksCalls atomic.Int64
	eks := countingEKS(&eksCalls, nil)
	gke := newGKEProvider(mockTokenSource(&oauth2.Token{}, nil))
	gke.getCluster = func(context.Context, oauth2.TokenSource, string, string, string) (clusterTLS, error) {
		gkeCalls.Add(1)

		return clusterTLS{host: "34.120.0.10", caData: "Y2E="}, nil
	}
	aks := aksKubeconfigServer(t, &aksCalls)
	for _, tc := range []struct {
		name    string
		resolve func(context.Context) error
		calls   *atomic.Int64
		want    bootCall
	}{
		{"eks", func(ctx context.Context) error {
			_, err := eks.resolveCluster(ctx, &EKSAuthArgs{ClusterName: bootEKSCluster})
			return err
		}, &eksCalls, bootCall{"eks", "DescribeCluster", "eks/us-east-1/c1", true, nil}},
		{"gke", func(ctx context.Context) error {
			_, err := gke.resolveCluster(ctx, &GKEAuthArgs{ClusterName: "c1", Location: "us-central1-f", Project: "p-1"})
			return err
		}, &gkeCalls, bootCall{"gke", "clusters.get", "gke/p-1/us-central1-f/c1", true, nil}},
		{"aks", func(ctx context.Context) error {
			_, err := aks.getClusterConfig(ctx, &AKSAuthArgs{
				ClusterName: "c1", ResourceGroup: "rg", SubscriptionID: bootSub,
			})
			return err
		}, &aksCalls, bootCall{"aks", "ListClusterUserCredentials", "aks/" + bootSub + "/rg/c1", true, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, first := observed(t.Context())
			if err := tc.resolve(ctx); err != nil {
				t.Fatal(err)
			}
			ctx, again := observed(t.Context())
			if err := tc.resolve(ctx); err != nil {
				t.Fatal(err)
			}
			if got := first.snapshot(); !slices.Equal(got, []bootCall{tc.want}) || len(again.snapshot()) != 0 ||
				tc.calls.Load() != 1 {
				t.Errorf("first %+v, cached %+v, %d vendor calls; want %+v once", got, again.snapshot(),
					tc.calls.Load(), tc.want)
			}
		})
	}
}

// TestObserveBootstrap_AFailedCallIsReportedEachTime pins that a resolution error ends the reported call with
// that error and, since failures are not cached, the next resolution calls and reports again.
func TestObserveBootstrap_AFailedCallIsReportedEachTime(t *testing.T) {
	t.Parallel()
	var n atomic.Int64
	errMissing := errors.New("ResourceNotFoundException")
	p := countingEKS(&n, errMissing)
	for range 2 {
		ctx, o := observed(t.Context())
		if _, err := p.resolveCluster(ctx, &EKSAuthArgs{ClusterName: bootEKSCluster}); !errors.Is(err, errMissing) {
			t.Fatalf("resolveCluster = %v", err)
		}
		if got := o.snapshot(); len(got) != 1 || !got[0].ended || !errors.Is(got[0].err, errMissing) {
			t.Errorf("reported %+v, want one call ended with the vendor error", got)
		}
	}
	if n.Load() != 2 {
		t.Errorf("%d vendor calls, want 2", n.Load())
	}
}

// TestObserveBootstrap_ARefusedCallSendsNothing pins that an observer that refuses a call stops it before the
// vendor is called, for a resolution and for the ClusterRole fetch, and that the refusal is the error.
func TestObserveBootstrap_ARefusedCallSendsNothing(t *testing.T) {
	t.Parallel()
	errAudit := errors.New("audit write failed")
	var n atomic.Int64
	p := countingEKS(&n, nil)
	var fetches atomic.Int64
	p.fetchView = func(context.Context, *EKSAuthArgs) (*k8sauthz.ViewPolicy, error) {
		fetches.Add(1)

		return viewPolicyAllowingPods(), nil
	}
	ctx := WithBootstrapObserver(t.Context(), &fakeObserver{refuse: errAudit})
	args := &EKSAuthArgs{ClusterName: bootEKSCluster}
	if _, err := p.resolveCluster(ctx, args); !errors.Is(err, errAudit) {
		t.Errorf("resolveCluster = %v, want the refusal", err)
	}
	if _, err := p.resolveViewPolicy(ctx, args); !errors.Is(err, errAudit) {
		t.Errorf("resolveViewPolicy = %v, want the refusal", err)
	}
	if n.Load() != 0 || fetches.Load() != 0 {
		t.Errorf("%d DescribeCluster calls and %d ClusterRole fetches after a refusal, want none", n.Load(),
			fetches.Load())
	}
}

// TestObserveBootstrap_ClusterRoleFetch pins the ClusterRole fetch's report for all four connectors: the
// connector, the call name and the cluster target with the role appended.
func TestObserveBootstrap_ClusterRoleFetch(t *testing.T) {
	t.Parallel()
	fetch := func(context.Context) (*k8sauthz.ViewPolicy, error) { return viewPolicyAllowingPods(), nil }
	eks := newEKSProvider(aws.Config{Region: "us-east-1"})
	eks.fetchView = func(ctx context.Context, _ *EKSAuthArgs) (*k8sauthz.ViewPolicy, error) { return fetch(ctx) }
	gke := newGKEProvider(mockTokenSource(&oauth2.Token{}, nil))
	gke.fetchView = func(ctx context.Context, _ *GKEAuthArgs) (*k8sauthz.ViewPolicy, error) { return fetch(ctx) }
	gke.clusterRole = "reader"
	aks := newAKSProvider(mockCredential(azcore.AccessToken{}, nil), cloud.Configuration{})
	aks.fetchView = func(ctx context.Context, _ *AKSAuthArgs) (*k8sauthz.ViewPolicy, error) { return fetch(ctx) }
	kube := refProvider()
	kube.fetchView = func(ctx context.Context, _ *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
		return fetch(ctx)
	}
	for _, tc := range []struct {
		name    string
		resolve func(context.Context) error
		want    bootCall
	}{
		{"eks", func(ctx context.Context) error {
			_, err := eks.resolveViewPolicy(ctx, &EKSAuthArgs{ClusterName: "c1", Region: "eu-west-1"})
			return err
		}, bootCall{"eks", "clusterrole", "eks/eu-west-1/c1 clusterroles/view", true, nil}},
		{"gke", func(ctx context.Context) error {
			_, err := gke.resolveViewPolicy(ctx, &GKEAuthArgs{ClusterName: "c1", Location: "l", Project: "p-1"})
			return err
		}, bootCall{"gke", "clusterrole", "gke/p-1/l/c1 clusterroles/reader", true, nil}},
		{"aks", func(ctx context.Context) error {
			_, err := aks.resolveViewPolicy(ctx, &AKSAuthArgs{
				ClusterName: "c1", ResourceGroup: "rg", SubscriptionID: bootSub,
			})
			return err
		}, bootCall{"aks", "clusterrole", "aks/" + bootSub + "/rg/c1 clusterroles/view", true, nil}},
		{"kubernetes", func(ctx context.Context) error {
			_, err := kube.resolveViewPolicy(ctx, nil)
			return err
		}, bootCall{"kubernetes", "clusterrole", "kubernetes/10.0.0.1:6443 clusterroles/view", true, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, o := observed(t.Context())
			if err := tc.resolve(ctx); err != nil {
				t.Fatal(err)
			}
			if got := o.snapshot(); !slices.Equal(got, []bootCall{tc.want}) {
				t.Errorf("reported %+v, want %+v", got, tc.want)
			}
		})
	}
}

// callerKey tags a caller's context, so a fake vendor call can tell whose context it runs under.
type callerKey struct{}

// TestObserveBootstrap_OnlyTheCallerThatStartsACallReportsIt pins that each vendor call is reported once, to the
// observer of the caller whose context it runs under. Two callers ask for one cluster while the first call is
// held; the second either joins that call or, if it arrives after the call ended, is served from the cache or
// starts its own, and the assertion holds on every path: a joined or cached caller reports nothing.
func TestObserveBootstrap_OnlyTheCallerThatStartsACallReportsIt(t *testing.T) {
	t.Parallel()
	release, entered := make(chan struct{}), make(chan struct{}, 2)
	var mu sync.Mutex
	ranUnder := map[string]int{}
	p := newEKSProvider(aws.Config{Region: "us-east-1"})
	p.describeCluster = func(ctx context.Context, _ aws.Config, _ string) (clusterTLS, error) {
		mu.Lock()
		ranUnder[ctx.Value(callerKey{}).(string)]++
		mu.Unlock()
		entered <- struct{}{}
		<-release

		return clusterTLS{host: "h", caData: "Y2E="}, nil
	}
	observers := map[string]*fakeObserver{"A": {}, "B": {}}
	var wg sync.WaitGroup
	call := func(who string) {
		ctx := WithBootstrapObserver(context.WithValue(t.Context(), callerKey{}, who), observers[who])
		wg.Go(func() {
			if _, err := p.resolveCluster(ctx, &EKSAuthArgs{ClusterName: bootEKSCluster}); err != nil {
				t.Error(err)
			}
		})
	}
	call("A")
	<-entered
	call("B")
	close(release)
	wg.Wait()
	for who, o := range observers {
		if got := len(o.snapshot()); got != ranUnder[who] {
			t.Errorf("caller %s reported %d calls, ran %d", who, got, ranUnder[who])
		}
	}
	if ranUnder["A"] != 1 {
		t.Errorf("the first caller's call ran %d times under its context, want 1", ranUnder["A"])
	}
}

// TestObserveBootstrap_ACallEndsAfterItsCallerGaveUp pins that a call still running when its caller stops waiting
// is ended when it finishes, so its result is reported after the caller returned.
func TestObserveBootstrap_ACallEndsAfterItsCallerGaveUp(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	p := newEKSProvider(aws.Config{Region: "us-east-1"})
	started := make(chan struct{})
	p.describeCluster = func(context.Context, aws.Config, string) (clusterTLS, error) {
		close(started)
		<-release

		return clusterTLS{host: "h", caData: "Y2E="}, nil
	}
	o := &fakeObserver{ended: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(WithBootstrapObserver(t.Context(), o))
	go func() {
		<-started
		cancel()
	}()
	if _, err := p.resolveCluster(ctx, &EKSAuthArgs{ClusterName: bootEKSCluster}); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolveCluster = %v, want the caller's cancellation", err)
	}
	if got := o.snapshot(); len(got) != 1 || got[0].ended {
		t.Fatalf("before the call finished: %+v, want one call not yet ended", got)
	}
	close(release)
	select {
	case <-o.ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the call never ended after it finished")
	}
	if got := o.snapshot(); !got[0].ended || got[0].err != nil {
		t.Errorf("after the call finished: %+v, want it ended with no error", got)
	}
}
