package auth

import (
	"errors"
	"fmt"
	"testing"
)

func TestShouldEmit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		policy   emitPolicy
		explicit bool
		verbose  bool
		want     bool
	}{
		{"always/ambient/quiet", emitAlways, false, false, true},
		{"always/explicit", emitAlways, true, false, true},
		{"explicit-or-verbose/ambient/quiet", emitWhenExplicitOrVerbose, false, false, false},
		{"explicit-or-verbose/explicit", emitWhenExplicitOrVerbose, true, false, true},
		{"explicit-or-verbose/verbose", emitWhenExplicitOrVerbose, false, true, true},
		{"explicit-or-verbose/both", emitWhenExplicitOrVerbose, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldEmit(tc.policy, tc.explicit, tc.verbose); got != tc.want {
				t.Fatalf("shouldEmit(%v,%v,%v) = %v, want %v", tc.policy, tc.explicit, tc.verbose, got, tc.want)
			}
		})
	}
}

func TestKubeSkipPolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want emitPolicy
	}{
		{"no current context", ErrNoCurrentContext, emitWhenExplicitOrVerbose},
		{"unsupported feature", ErrUnsupportedFeature, emitWhenExplicitOrVerbose},
		{"wrapped unsupported via fmt", fmt.Errorf("x: %w", ErrUnsupportedFeature), emitWhenExplicitOrVerbose},
		{"lookalike text not wrapped is structural", errors.New("unsupported kubeconfig feature"), emitAlways},
		{"structural default", errors.New("kubernetes: context \"x\" not found"), emitAlways},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := kubeSkipPolicy(tc.err); got != tc.want {
				t.Fatalf("kubeSkipPolicy(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestAWSSkipResult(t *testing.T) {
	t.Parallel()

	t.Run("load failure is always loud", func(t *testing.T) {
		t.Parallel()
		skipped, policy, msg := awsSkipResult(errors.New("bad config"), nil)
		if !skipped || policy != emitAlways ||
			msg != "aws_hardening: skipped (config load failed): bad config" {
			t.Fatalf("got %v %v %q", skipped, policy, msg)
		}
	})

	t.Run("retrieve failure is explicit-gated", func(t *testing.T) {
		t.Parallel()
		skipped, policy, msg := awsSkipResult(nil, errors.New("no creds"))
		if !skipped || policy != emitWhenExplicitOrVerbose ||
			msg != "aws_hardening: skipped (no usable credentials): no creds" {
			t.Fatalf("got %v %v %q", skipped, policy, msg)
		}
	})

	t.Run("success does not skip", func(t *testing.T) {
		t.Parallel()
		if skipped, _, _ := awsSkipResult(nil, nil); skipped {
			t.Fatal("expected no skip")
		}
	})
}

func TestGCPSkipResult(t *testing.T) {
	t.Parallel()

	t.Run("find failure", func(t *testing.T) {
		t.Parallel()
		skipped, msg := gcpSkipResult(errors.New("no adc"), nil)
		if !skipped || msg != "gcp_hardening: skipped (no usable credentials): no adc" {
			t.Fatalf("got %v %q", skipped, msg)
		}
	})

	t.Run("probe failure", func(t *testing.T) {
		t.Parallel()
		skipped, msg := gcpSkipResult(nil, errors.New("token denied"))
		if !skipped || msg != "gcp_hardening: skipped (no usable credentials): token denied" {
			t.Fatalf("got %v %q", skipped, msg)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		if skipped, _ := gcpSkipResult(nil, nil); skipped {
			t.Fatal("expected no skip")
		}
	})
}

func TestAzureSkipResult(t *testing.T) {
	t.Parallel()

	t.Run("chain failure", func(t *testing.T) {
		t.Parallel()
		skipped, msg := azureSkipResult(errors.New("no chain"), nil)
		if !skipped || msg != "azure_hardening: skipped (no usable credentials): no chain" {
			t.Fatalf("got %v %q", skipped, msg)
		}
	})

	t.Run("probe failure", func(t *testing.T) {
		t.Parallel()
		skipped, msg := azureSkipResult(nil, errors.New("arm denied"))
		if !skipped || msg != "azure_hardening: skipped (no usable credentials): arm denied" {
			t.Fatalf("got %v %q", skipped, msg)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		if skipped, _ := azureSkipResult(nil, nil); skipped {
			t.Fatal("expected no skip")
		}
	})
}

func TestKubeSkipResult(t *testing.T) {
	t.Parallel()

	t.Run("load failure is always loud", func(t *testing.T) {
		t.Parallel()
		skipped, policy, msg := kubeSkipResult(errors.New("bad kubeconfig"), nil)
		if !skipped || policy != emitAlways ||
			msg != "kubernetes_hardening: skipped (load kubeconfig): bad kubeconfig" {
			t.Fatalf("got %v %v %q", skipped, policy, msg)
		}
	})

	t.Run("no-current-context is explicit-gated", func(t *testing.T) {
		t.Parallel()
		skipped, policy, msg := kubeSkipResult(nil, ErrNoCurrentContext)
		if !skipped || policy != emitWhenExplicitOrVerbose ||
			msg != "kubernetes_hardening: skipped: "+ErrNoCurrentContext.Error() {
			t.Fatalf("got %v %v %q", skipped, policy, msg)
		}
	})

	t.Run("structural is always loud", func(t *testing.T) {
		t.Parallel()
		skipped, policy, _ := kubeSkipResult(nil, errors.New("kubernetes: read CA: open /x: no such file"))
		if !skipped || policy != emitAlways {
			t.Fatalf("got %v %v", skipped, policy)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		if skipped, _, _ := kubeSkipResult(nil, nil); skipped {
			t.Fatal("expected no skip")
		}
	})
}
