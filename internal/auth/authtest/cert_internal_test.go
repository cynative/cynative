package authtest

import (
	"crypto/x509"
	"testing"
)

func TestBuildLeafTemplate_Client(t *testing.T) {
	t.Parallel()

	tmpl := buildLeafTemplate(false)
	if len(tmpl.ExtKeyUsage) != 1 || tmpl.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("client ExtKeyUsage = %v, want [ClientAuth]", tmpl.ExtKeyUsage)
	}
	if tmpl.IPAddresses != nil || tmpl.DNSNames != nil {
		t.Error("client template must not set IPAddresses/DNSNames")
	}
}

func TestBuildLeafTemplate_Server(t *testing.T) {
	t.Parallel()

	tmpl := buildLeafTemplate(true)
	if len(tmpl.ExtKeyUsage) != 2 {
		t.Errorf("server ExtKeyUsage = %v, want client+server", tmpl.ExtKeyUsage)
	}
	if len(tmpl.IPAddresses) == 0 || len(tmpl.DNSNames) == 0 {
		t.Error("server template must set IPAddresses and DNSNames")
	}
}
