package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	awshardening "github.com/cynative/cynative/internal/auth/aws"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
)

// fakeTokenCred is a no-op azcore.TokenCredential for tests.
type fakeTokenCred struct{}

func (fakeTokenCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

// wantQuietSkip fails unless out is a skipped (no-provider) outcome whose single
// status is not visible (ambient-quiet).
func wantQuietSkip(t *testing.T, out connectorOutcome) {
	t.Helper()
	if len(out.providers) != 0 || out.visible[0] {
		t.Fatalf("out=%+v, want quiet skip", out)
	}
}

// wantLoudSkip fails unless out is a skipped (no-provider) outcome whose single
// status is visible (loud).
func wantLoudSkip(t *testing.T, out connectorOutcome) {
	t.Helper()
	if len(out.providers) != 0 || !out.visible[0] {
		t.Fatalf("out=%+v, want loud skip", out)
	}
}

// stubDeps returns a registrationDeps whose seams all succeed and whose builders
// return non-nil stub providers. Individual tests override the fields they probe.
func stubDeps() *registrationDeps {
	return &registrationDeps{ //nolint:exhaustruct // posture labels default empty.
		lookupEnv:      envFrom(nil),
		fileExists:     func(string) bool { return false },
		homeDir:        "/home/u",
		tokenForHost:   func(context.Context) (string, bool, error) { return "tok", true, nil },
		validateGithub: func(context.Context, string) (string, error) { return "@octocat", nil },
		discoverGitLab: func([]string) (glabCredential, error) {
			return glabCredential{AccessToken: "glpat-x"}, nil //nolint:exhaustruct // env PAT.
		},
		buildGitLab: func(GitLabHardeningConfig, string, glabCredential) (*gitlabProvider, error) {
			return &gitlabProvider{ //nolint:exhaustruct // bare.
				tokenSource: oauth2.StaticTokenSource(
					&oauth2.Token{AccessToken: "glpat-x"},
				), //nolint:exhaustruct // access.
			}, nil
		},
		validateGitLab: func(context.Context, *gitlabProvider) (string, error) { return "alice", nil },
		loadAWS:        func(context.Context) (aws.Config, error) { return aws.Config{}, nil }, //nolint:exhaustruct // zero cfg.
		retrieveAWS:    func(context.Context, aws.Config) error { return nil },
		validateAWS: func(context.Context, aws.Config) (string, string, string, error) {
			return "123 · arn:aws:iam::123:user/u", "arn:aws:iam::123:user/u", "123", nil
		},
		resolveScopeAWS: func(context.Context, string, string, aws.Config) (awshardening.ScopeResult, aws.CredentialsProvider) {
			return awshardening.ScopeResult{Mode: awshardening.CredScopeDisabled}, nil //nolint:exhaustruct // bare.
		},
		buildAWS: func(aws.Config, aws.CredentialsProvider) (*awsProvider, *eksProvider) {
			return &awsProvider{}, &eksProvider{} //nolint:exhaustruct // bare.
		},
		findGCP:       func(context.Context) (*google.Credentials, error) { return &google.Credentials{}, nil }, //nolint:exhaustruct // zero.
		probeGCP:      func(context.Context) error { return nil },
		gcpIdentity:   func(context.Context, *google.Credentials) string { return "proj · me@x" },
		buildGCP:      func(*google.Credentials) (*gcpProvider, *gkeProvider) { return &gcpProvider{}, &gkeProvider{} }, //nolint:exhaustruct // bare.
		newAzure:      func() (azcore.TokenCredential, error) { return fakeTokenCred{}, nil },
		probeAzure:    func(context.Context, azcore.TokenCredential) error { return nil },
		azureIdentity: func(context.Context, azcore.TokenCredential) string { return "me@tenant" },
		buildAzure:    func(azcore.TokenCredential) (*azureProvider, *aksProvider) { return &azureProvider{}, &aksProvider{} }, //nolint:exhaustruct // bare.
		loadKube:      func() (resolvedCluster, error, error) { return resolvedCluster{}, nil, nil },                           //nolint:exhaustruct // zero.
		buildKube:     func(resolvedCluster) *kubernetesProvider { return &kubernetesProvider{} },                              //nolint:exhaustruct // bare.
		probeKube:     func(context.Context, *kubernetesProvider) error { return nil },
	}
}

func TestRegisterAWS_Success(t *testing.T) {
	t.Parallel()
	out := stubDeps().registerAWS(context.Background(), false)
	if len(out.providers) != 2 || len(out.statuses) != 1 || len(out.visible) != 1 || !out.visible[0] {
		t.Fatalf("out=%+v, want 2 providers + 1 visible folded status", out)
	}
	if !out.statuses[0].Available || out.statuses[0].Identity != "123 · arn:aws:iam::123:user/u" {
		t.Fatalf("out=%+v, want aws identity", out)
	}
	if out.statuses[0].Managed != eksProviderName {
		t.Fatalf("aws status Managed=%q, want %q", out.statuses[0].Managed, eksProviderName)
	}
}

func TestRegisterAWS_Outcome(t *testing.T) {
	t.Parallel()

	t.Run("retrieve fail ambient quiet", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.retrieveAWS = func(context.Context, aws.Config) error { return errors.New("no creds") }
		out := d.registerAWS(context.Background(), false)
		if len(out.providers) != 0 || out.visible[0] {
			t.Fatalf("out=%+v, want quiet skip", out)
		}
	})

	t.Run("retrieve fail ambient verbose loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.retrieveAWS = func(context.Context, aws.Config) error { return errors.New("no creds") }
		out := d.registerAWS(context.Background(), true)
		if !out.visible[0] || out.statuses[0].Reason != "aws_hardening: skipped (no usable credentials): no creds" {
			t.Fatalf("out=%+v, want loud verbose skip with reason", out)
		}
	})

	t.Run("retrieve fail explicit loud by default", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.lookupEnv = envFrom(map[string]string{"AWS_PROFILE": "dev"})
		d.retrieveAWS = func(context.Context, aws.Config) error { return errors.New("no creds") }
		out := d.registerAWS(context.Background(), false)
		if len(out.providers) != 0 || !out.visible[0] {
			t.Fatalf("out=%+v, want explicit loud skip", out)
		}
	})

	t.Run("load fail loud and skips retrieve", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		retrieved := false
		d.loadAWS = func(context.Context) (aws.Config, error) { return aws.Config{}, errors.New("bad") } //nolint:exhaustruct // zero.
		d.retrieveAWS = func(context.Context, aws.Config) error { retrieved = true; return nil }
		out := d.registerAWS(context.Background(), false)
		if len(out.providers) != 0 || retrieved || !out.visible[0] {
			t.Fatalf("out=%+v retrieved=%v", out, retrieved)
		}
	})

	t.Run("retrieve fail explicit via default-profile config loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.awsDefaultProfileCreds = true // creds in ~/.aws/config [default], no env selector.
		d.retrieveAWS = func(context.Context, aws.Config) error { return errors.New("sso token expired") }
		out := d.registerAWS(context.Background(), false)
		if !out.visible[0] {
			t.Fatal("default-profile-config AWS retrieve-fail must be loud by default (no silent drop)")
		}
	})
}

// TestRegisterAWS_Liveness covers the STS GetCallerIdentity liveness check, the
// transient-error escalation, and the bounded probe context.
func TestRegisterAWS_Liveness(t *testing.T) {
	t.Parallel()

	t.Run("retrieve ok but STS validate fail ambient quiet", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.validateAWS = func(context.Context, aws.Config) (string, string, string, error) {
			return "", "", "", errors.New("InvalidClientTokenId")
		}
		out := d.registerAWS(context.Background(), false)
		if len(out.providers) != 0 || out.visible[0] {
			t.Fatalf("out=%+v (revoked key must skip, quiet when ambient)", out)
		}
	})

	t.Run("retrieve ok but STS validate fail explicit loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.lookupEnv = envFrom(map[string]string{"AWS_PROFILE": "dev"})
		d.validateAWS = func(context.Context, aws.Config) (string, string, string, error) {
			return "", "", "", errors.New("InvalidClientTokenId")
		}
		out := d.registerAWS(context.Background(), false)
		if len(out.providers) != 0 || !out.visible[0] {
			t.Fatalf("out=%+v (revoked explicit key must skip+loud)", out)
		}
	})

	t.Run("transient validate fail loud even ambient", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.validateAWS = func(context.Context, aws.Config) (string, string, string, error) {
			return "", "", "", context.DeadlineExceeded
		}
		out := d.registerAWS(context.Background(), false)
		if len(out.providers) != 0 || !out.visible[0] {
			t.Fatalf("out=%+v (transient ambient must be loud)", out)
		}
	})

	t.Run("validate not called when retrieve fails", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.retrieveAWS = func(context.Context, aws.Config) error { return errors.New("no creds") }
		validated := false
		d.validateAWS = func(context.Context, aws.Config) (string, string, string, error) {
			validated = true
			return "", "", "", nil
		}
		d.registerAWS(context.Background(), false)
		if validated {
			t.Fatal("validateAWS must not run when retrieve already failed")
		}
	})

	t.Run("probe ctx deadline is ~credentialProbeTimeout", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var remaining time.Duration
		var hadDeadline bool
		d.retrieveAWS = func(ctx context.Context, _ aws.Config) error {
			if dl, ok := ctx.Deadline(); ok {
				hadDeadline = true
				remaining = time.Until(dl)
			}

			return nil
		}
		d.registerAWS(context.Background(), false)
		// Pin the actual value (not just existence): a wrong const is caught.
		if !hadDeadline || remaining <= 4*time.Second || remaining > 5*time.Second {
			t.Fatalf("hadDeadline=%v remaining=%v, want in (4s, 5s]", hadDeadline, remaining)
		}
	})
}

func TestRegisterGCP_Outcome(t *testing.T) {
	t.Parallel()

	t.Run("ambient probe failure is quiet", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.probeGCP = func(context.Context) error { return errors.New("denied") }
		wantQuietSkip(t, d.registerGCP(context.Background(), false))
	})

	t.Run("explicit probe failure is loud with reason", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.lookupEnv = envFrom(map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/k"})
		d.probeGCP = func(context.Context) error { return errors.New("denied") }
		out := d.registerGCP(context.Background(), false)
		wantLoudSkip(t, out)
		if out.statuses[0].Reason == "" {
			t.Fatalf("out=%+v, want loud skip with reason", out)
		}
	})

	t.Run("ambient find failure is quiet", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.findGCP = func(context.Context) (*google.Credentials, error) { return nil, errors.New("no adc") }
		wantQuietSkip(t, d.registerGCP(context.Background(), false))
	})

	t.Run("ambient find failure verbose loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.findGCP = func(context.Context) (*google.Credentials, error) { return nil, errors.New("no adc") }
		wantLoudSkip(t, d.registerGCP(context.Background(), true))
	})

	t.Run("ambient transient probe failure is loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.probeGCP = func(context.Context) error { return context.DeadlineExceeded }
		wantLoudSkip(t, d.registerGCP(context.Background(), false))
	})

	t.Run("success registers with identity", func(t *testing.T) {
		t.Parallel()
		out := stubDeps().registerGCP(context.Background(), false)
		if len(out.providers) != 2 || len(out.statuses) != 1 || len(out.visible) != 1 || !out.visible[0] ||
			!out.statuses[0].Available || out.statuses[0].Identity != "proj · me@x" {
			t.Fatalf("out=%+v, want 2 providers + gcp identity", out)
		}
		if out.statuses[0].Managed != gkeProviderName {
			t.Fatalf("gcp status Managed=%q, want %q", out.statuses[0].Managed, gkeProviderName)
		}
	})

	t.Run("probe ctx carries a deadline", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var hadDeadline bool
		d.probeGCP = func(ctx context.Context) error { _, hadDeadline = ctx.Deadline(); return nil }
		d.registerGCP(context.Background(), false)
		if !hadDeadline {
			t.Fatal("registerGCP must bound the probe ctx with a deadline")
		}
	})

	t.Run("findGCP ctx is unbounded (registered source not poisoned)", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var findHadDeadline bool
		d.findGCP = func(ctx context.Context) (*google.Credentials, error) {
			_, findHadDeadline = ctx.Deadline()

			return &google.Credentials{}, nil //nolint:exhaustruct // zero creds.
		}
		d.registerGCP(context.Background(), false)
		// The returned TokenSource retains this ctx for the session, so it must
		// NOT be the bounded/cancelled probe ctx.
		if findHadDeadline {
			t.Fatal("findGCP must receive an unbounded ctx (its TokenSource is retained for the session)")
		}
	})
}

func TestRegisterAzure_Outcome(t *testing.T) {
	t.Parallel()

	t.Run("explicit probe failure loud with reason", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.lookupEnv = envFrom(map[string]string{"AZURE_TENANT_ID": "t"})
		d.probeAzure = func(context.Context, azcore.TokenCredential) error { return errors.New("arm denied") }
		out := d.registerAzure(context.Background(), false)
		wantLoudSkip(t, out)
		if out.statuses[0].Reason != "azure_hardening: skipped (no usable credentials): arm denied" {
			t.Fatalf("out=%+v, want loud skip with reason", out)
		}
	})

	t.Run("chain failure ambient quiet", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.newAzure = func() (azcore.TokenCredential, error) { return nil, errors.New("no chain") }
		wantQuietSkip(t, d.registerAzure(context.Background(), false))
	})

	t.Run("chain failure explicit loud by default", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.lookupEnv = envFrom(map[string]string{"AZURE_TENANT_ID": "t"})
		d.newAzure = func() (azcore.TokenCredential, error) { return nil, errors.New("no chain") }
		wantLoudSkip(t, d.registerAzure(context.Background(), false))
	})

	t.Run("chain failure ambient verbose loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.newAzure = func() (azcore.TokenCredential, error) { return nil, errors.New("no chain") }
		wantLoudSkip(t, d.registerAzure(context.Background(), true))
	})

	t.Run("ambient probe failure is quiet (no optimistic registration)", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.probeAzure = func(context.Context, azcore.TokenCredential) error {
			return errors.New("no managed identity")
		}
		wantQuietSkip(t, d.registerAzure(context.Background(), false))
	})

	t.Run("ambient transient probe failure is loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.probeAzure = func(context.Context, azcore.TokenCredential) error { return context.DeadlineExceeded }
		wantLoudSkip(t, d.registerAzure(context.Background(), false))
	})

	t.Run("success registers with identity", func(t *testing.T) {
		t.Parallel()
		out := stubDeps().registerAzure(context.Background(), false)
		if len(out.providers) != 2 || len(out.statuses) != 1 || len(out.visible) != 1 || !out.visible[0] ||
			!out.statuses[0].Available || out.statuses[0].Identity != "me@tenant" {
			t.Fatalf("out=%+v, want 2 providers + azure identity", out)
		}
		if out.statuses[0].Managed != aksProviderName {
			t.Fatalf("azure status Managed=%q, want %q", out.statuses[0].Managed, aksProviderName)
		}
	})

	t.Run("probe ctx carries a deadline", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var hadDeadline bool
		d.probeAzure = func(ctx context.Context, _ azcore.TokenCredential) error {
			_, hadDeadline = ctx.Deadline()

			return nil
		}
		d.registerAzure(context.Background(), false)
		if !hadDeadline {
			t.Fatal("registerAzure must bound the probe ctx with a deadline")
		}
	})
}

func TestRegisterKube_Outcome(t *testing.T) {
	t.Parallel()

	t.Run("no-current-context ambient quiet", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.loadKube = func() (resolvedCluster, error, error) { //nolint:exhaustruct // zero cluster.
			return resolvedCluster{}, nil, ErrNoCurrentContext
		}
		out := d.registerKube(false)
		if len(out.providers) != 0 || out.visible[0] {
			t.Fatalf("out=%+v, want quiet skip", out)
		}
	})

	t.Run("no-current-context explicit (KUBECONFIG) loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.lookupEnv = envFrom(map[string]string{"KUBECONFIG": "/k"})
		d.loadKube = func() (resolvedCluster, error, error) { //nolint:exhaustruct // zero cluster.
			return resolvedCluster{}, nil, ErrNoCurrentContext
		}
		out := d.registerKube(false)
		if !out.visible[0] {
			t.Fatal("explicit KUBECONFIG no-current-context must be loud")
		}
	})

	t.Run("no-current-context ambient verbose loud", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.loadKube = func() (resolvedCluster, error, error) { //nolint:exhaustruct // zero cluster.
			return resolvedCluster{}, nil, ErrNoCurrentContext
		}
		out := d.registerKube(true)
		if !out.visible[0] {
			t.Fatal("ambient no-current-context must be shown under --verbose")
		}
	})

	t.Run("structural loud even ambient", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.loadKube = func() (resolvedCluster, error, error) { //nolint:exhaustruct // zero cluster.
			return resolvedCluster{}, nil, errors.New("kubernetes: read CA: open /x")
		}
		out := d.registerKube(false)
		if len(out.providers) != 0 || !out.visible[0] {
			t.Fatalf("out=%+v, want loud skip", out)
		}
	})

	t.Run("success registers with host identity", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.loadKube = func() (resolvedCluster, error, error) { //nolint:exhaustruct // host only.
			return resolvedCluster{host: "k8s.example"}, nil, nil
		}
		out := d.registerKube(false)
		if len(out.providers) != 1 || !out.statuses[0].Available || out.statuses[0].Identity != "k8s.example" {
			t.Fatalf("out=%+v, want 1 provider + host identity", out)
		}
	})
}

func TestRegisterKube_Eager(t *testing.T) {
	t.Parallel()

	t.Run("build + probe success → registered", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		got := d.registerKube(false)
		if len(got.providers) != 1 || !got.statuses[0].Available {
			t.Fatalf("want registered, got %+v", got)
		}
	})

	t.Run("probe fail ambient → quiet unavailable", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.probeKube = func(context.Context, *kubernetesProvider) error { return errors.New("unreachable") }
		got := d.registerKube(false)
		if len(got.providers) != 0 || got.statuses[0].Available || got.visible[0] {
			t.Fatalf("want quiet unavailable, got %+v", got)
		}
	})

	t.Run("probe fail verbose → loud with cluster validation failed", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.probeKube = func(context.Context, *kubernetesProvider) error { return errors.New("unreachable") }
		got := d.registerKube(true)
		if len(got.providers) != 0 || got.statuses[0].Available || !got.visible[0] {
			t.Fatalf("want loud unavailable, got %+v", got)
		}
		if !strings.Contains(got.statuses[0].Reason, "cluster validation failed") {
			t.Fatalf("want 'cluster validation failed' reason, got %q", got.statuses[0].Reason)
		}
	})

	t.Run("transient probe error → retried twice, loud even ambient", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var calls int
		d.probeKube = func(context.Context, *kubernetesProvider) error {
			calls++

			return context.DeadlineExceeded
		}
		got := d.registerKube(false)
		if calls != 2 || !got.visible[0] || got.statuses[0].Available {
			t.Fatalf("want 2 calls + loud unavailable, got calls=%d %+v", calls, got)
		}
	})

	t.Run("probe receives a bounded ctx", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var hasDeadline bool
		d.probeKube = func(ctx context.Context, _ *kubernetesProvider) error {
			_, hasDeadline = ctx.Deadline()

			return nil
		}
		_ = d.registerKube(false)
		if !hasDeadline {
			t.Fatal("probeKube must receive a deadline-bounded ctx")
		}
	})
}

func TestBoundedIdentity(t *testing.T) {
	t.Parallel()

	t.Run("returns fn result before timeout", func(t *testing.T) {
		t.Parallel()
		got := boundedIdentity(context.Background(), time.Second, func(context.Context) string { return "id" })
		if got != "id" {
			t.Errorf("got %q, want id", got)
		}
	})

	t.Run("returns empty when fn outruns the timeout", func(t *testing.T) {
		t.Parallel()
		// fn ignores ctx and sleeps past the 1ms bound → boundedIdentity must not wait.
		got := boundedIdentity(context.Background(), time.Millisecond, func(context.Context) string {
			time.Sleep(50 * time.Millisecond)

			return "late"
		})
		if got != "" {
			t.Errorf("got %q, want empty (hard-bounded)", got)
		}
	})
}

func TestGithubOutcome(t *testing.T) {
	t.Parallel()

	t.Run("absent token → empty outcome (quiet)", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.tokenForHost = func(context.Context) (string, bool, error) { return "", false, nil }
		got := d.githubOutcome(context.Background(), GithubHardeningConfig{}, false)
		if len(got.providers) != 0 || len(got.statuses) != 0 {
			t.Fatalf("want empty outcome, got %+v", got)
		}
	})

	t.Run("resolution error → loud skip", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.tokenForHost = func(context.Context) (string, bool, error) { return "", false, errors.New("keyring") }
		got := d.githubOutcome(context.Background(), GithubHardeningConfig{}, false)
		if len(got.providers) != 0 || len(got.visible) != 1 || !got.visible[0] || got.statuses[0].Available {
			t.Fatalf("want loud unavailable skip, got %+v", got)
		}
	})

	t.Run("valid (baseline) → registered with identity, quiet posture", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		got := d.githubOutcome(context.Background(), GithubHardeningConfig{}, false)
		if len(got.providers) != 1 || !got.statuses[0].Available ||
			got.statuses[0].Identity != "@octocat" || got.statuses[0].Warn {
			t.Fatalf("want registered+@octocat, quiet, got %+v", got)
		}
	})

	t.Run("valid + default:write → registered with loud exposure posture", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		cfg := GithubHardeningConfig{Permissions: map[string]string{"default": "write"}}
		got := d.githubOutcome(context.Background(), cfg, false)
		wantPosture, _ := githubPosture(githubhardening.BuildExposure(cfg.Permissions), cfg.Permissions)
		if len(got.providers) != 1 || !got.statuses[0].Available ||
			!got.statuses[0].Warn || got.statuses[0].Posture != wantPosture {
			t.Fatalf("want registered + Warn=true + Posture=%q, got %+v", wantPosture, got)
		}
	})

	t.Run("invalid (non-transient) → loud skip", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.validateGithub = func(context.Context, string) (string, error) {
			return "", &githubStatusError{code: http.StatusUnauthorized}
		}
		got := d.githubOutcome(context.Background(), GithubHardeningConfig{}, false)
		if len(got.providers) != 0 || !got.visible[0] || got.statuses[0].Available {
			t.Fatalf("want loud skip, got %+v", got)
		}
	})

	t.Run("transient → retried twice then loud skip", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var calls int
		d.validateGithub = func(context.Context, string) (string, error) {
			calls++

			return "", &githubStatusError{code: http.StatusServiceUnavailable}
		}
		got := d.githubOutcome(context.Background(), GithubHardeningConfig{}, false)
		if calls != 2 || len(got.providers) != 0 || !got.visible[0] {
			t.Fatalf("want 2 calls + loud skip, got calls=%d %+v", calls, got)
		}
	})
}

func TestGitlabOutcome(t *testing.T) {
	t.Parallel()

	t.Run("valid → registered with @username identity", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		got := d.gitlabOutcome(context.Background(), GitLabHardeningConfig{}, false) //nolint:exhaustruct // zero cfg.
		if len(got.providers) != 1 || !got.statuses[0].Available || got.statuses[0].Identity != "@alice" {
			t.Fatalf("want registered+@alice, got %+v", got)
		}
	})

	t.Run("self-managed → @username · host identity", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		cfg := GitLabHardeningConfig{APIHost: "gitlab.internal"} //nolint:exhaustruct // only api_host.
		got := d.gitlabOutcome(context.Background(), cfg, false)
		if got.statuses[0].Identity != "@alice · gitlab.internal" {
			t.Fatalf("want '@alice · gitlab.internal', got %q", got.statuses[0].Identity)
		}
	})

	t.Run("valid + default:write permissions → loud posture", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		//nolint:exhaustruct // only permissions.
		cfg := GitLabHardeningConfig{Permissions: map[string]string{"default": "write"}}
		got := d.gitlabOutcome(context.Background(), cfg, false)
		wantPosture, _ := gitlabPosture(gitlabclass.BuildExposure(cfg.Permissions), cfg.Permissions)
		if !got.statuses[0].Warn || got.statuses[0].Posture != wantPosture {
			t.Fatalf("want Warn=true + Posture=%q, got %+v", wantPosture, got)
		}
	})

	// An expired/dead OAuth session arrives as errGitLabRefreshDead from the token
	// source through validateGitLab → the existing wrapper renders a loud,
	// unavailable skip whose Reason carries both the wrapper text and the precise
	// errGitLabRefreshDead operator steer.
	t.Run("dead OAuth session → loud skip with precise reason", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.validateGitLab = func(context.Context, *gitlabProvider) (string, error) {
			return "", fmt.Errorf("gitlab: resolve access token: %w", errGitLabRefreshDead)
		}
		got := d.gitlabOutcome(context.Background(), GitLabHardeningConfig{}, false) //nolint:exhaustruct // zero cfg.
		if len(got.providers) != 0 || len(got.visible) != 1 || !got.visible[0] || got.statuses[0].Available {
			t.Fatalf("want loud unavailable skip, got %+v", got)
		}
		reason := got.statuses[0].Reason
		if !strings.Contains(reason, "token validation failed") ||
			!strings.Contains(reason, "run `glab auth login`") {
			t.Fatalf("reason %q must carry wrapper text + the errGitLabRefreshDead steer", reason)
		}
	})
}

func TestGitlabOutcome_Skips(t *testing.T) {
	t.Parallel()

	t.Run("absent token → empty outcome (quiet)", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		d.discoverGitLab = func([]string) (glabCredential, error) {
			return glabCredential{}, nil //nolint:exhaustruct // absent.
		}
		got := d.gitlabOutcome(context.Background(), GitLabHardeningConfig{}, false) //nolint:exhaustruct // zero cfg.
		if len(got.providers) != 0 || len(got.statuses) != 0 {
			t.Fatalf("want empty outcome, got %+v", got)
		}
	})

	// Discovery error (malformed glab config), build error (ca_cert), and invalid
	// token (non-transient) all yield a loud, visible, unavailable skip.
	loudCases := map[string]func(*registrationDeps){
		"discovery error": func(d *registrationDeps) {
			d.discoverGitLab = func([]string) (glabCredential, error) {
				return glabCredential{}, errors.New("parse glab config") //nolint:exhaustruct // err.
			}
		},
		"build error": func(d *registrationDeps) {
			d.buildGitLab = func(GitLabHardeningConfig, string, glabCredential) (*gitlabProvider, error) {
				return nil, errors.New("ca_cert unreadable")
			}
		},
		"invalid token (non-transient)": func(d *registrationDeps) {
			d.validateGitLab = func(context.Context, *gitlabProvider) (string, error) { return "", errors.New("401") }
		},
	}
	for name, mut := range loudCases {
		t.Run(name+" → loud skip", func(t *testing.T) {
			t.Parallel()
			d := stubDeps()
			mut(d)
			got := d.gitlabOutcome(
				context.Background(),
				GitLabHardeningConfig{},
				false,
			) //nolint:exhaustruct // zero cfg.
			if len(got.providers) != 0 || len(got.visible) != 1 || !got.visible[0] || got.statuses[0].Available {
				t.Fatalf("want loud unavailable skip, got %+v", got)
			}
		})
	}

	t.Run("transient → retried twice then loud skip", func(t *testing.T) {
		t.Parallel()
		d := stubDeps()
		var calls int
		d.validateGitLab = func(context.Context, *gitlabProvider) (string, error) {
			calls++

			return "", context.DeadlineExceeded
		}
		got := d.gitlabOutcome(context.Background(), GitLabHardeningConfig{}, false) //nolint:exhaustruct // zero cfg.
		if calls != 2 || len(got.providers) != 0 || !got.visible[0] {
			t.Fatalf("want 2 calls + loud skip, got calls=%d %+v", calls, got)
		}
	})
}

func TestRegisterAWS_ScopeDegraded_rendersDisabledStillAvailable(t *testing.T) {
	t.Parallel()
	d := stubDeps()
	d.validateAWS = func(context.Context, aws.Config) (string, string, string, error) {
		return "123 · arn:aws:sts::123:assumed-role/SSO/sess", "arn:aws:sts::123:assumed-role/SSO/sess", "123", nil
	}
	d.resolveScopeAWS = func(context.Context, string, string, aws.Config) (awshardening.ScopeResult, aws.CredentialsProvider) {
		return awshardening.ScopeResult{ //nolint:exhaustruct // mode+reason only.
			Mode:   awshardening.CredScopeDisabled,
			Reason: "assume_role_unavailable",
		}, nil
	}
	out := d.registerAWS(context.Background(), false)
	if len(out.providers) != 2 || !out.statuses[0].Available {
		t.Fatalf("degrade must keep AWS available: %+v", out)
	}
	if !strings.Contains(out.statuses[0].Posture, "enforced=client ·") {
		t.Fatalf("posture=%q, want enforced=client · …", out.statuses[0].Posture)
	}
}

func TestRegisterAWS_ScopeAssumeRole_rendersEnforcedLabel(t *testing.T) {
	t.Parallel()
	d := stubDeps()
	d.validateAWS = func(context.Context, aws.Config) (string, string, string, error) {
		return "123 · arn:aws:iam::123:user/u", "arn:aws:iam::123:user/u", "123", nil
	}
	d.resolveScopeAWS = func(context.Context, string, string, aws.Config) (awshardening.ScopeResult, aws.CredentialsProvider) {
		return awshardening.ScopeResult{ //nolint:exhaustruct // mode+verified only.
			Mode:     awshardening.CredScopeAssumeRole,
			Verified: true,
		}, nil
	}
	out := d.registerAWS(context.Background(), false)
	if !strings.Contains(out.statuses[0].Posture, "enforced=client+aws ·") {
		t.Fatalf("posture=%q, want enforced=client+aws · …", out.statuses[0].Posture)
	}
}
