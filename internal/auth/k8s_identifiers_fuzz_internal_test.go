package auth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// The fuzz targets pin the property the identifier grammars exist for: every value validate accepts reaches the
// control-plane API as exactly the template path (and, for EKS, exactly the configured partition's host). The seeds
// are the whole gate in make check, so each grammar branch has one.

func FuzzGKEIdentifiersKeepTheRequestPath(f *testing.F) {
	for _, s := range [][3]string{
		{"my-project", "us-central1", "prod-1"},
		{"123456789012", "us-central1-a", "c"},
		{"my-project", "us-central1", "c/nodePools"},
		{"my-project", "us-central1", ".."},
		{"example.com:proj", "us-central1", "c"},
		{"my-project", "us-central1/x", "c"},
		{"my-project", "us-central1", "c:get"},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, project, location, cluster string) {
		if (&GKEAuthArgs{Project: project, Location: location, ClusterName: cluster}).validate() != nil {
			return
		}
		u := gkeRequestURL(t, project, location, cluster)
		want := "/v1/projects/" + project + "/locations/" + location + "/clusters/" + cluster
		if u.Host != "container.googleapis.com" || u.EscapedPath() != want ||
			u.RawQuery != "alt=json&prettyPrint=false" {
			t.Errorf("accepted %q %q %q, request went to %s", project, location, cluster, u)
		}
	})
}

func FuzzEKSIdentifiersKeepTheRequestPath(f *testing.F) {
	for _, s := range [][2]string{
		{"prod", ""},
		{"Prod_1", "eu-west-1"},
		{"a/b", "us-east-1"},
		{"..", "us-east-1"},
		{"prod", "cn-north-1"},
		{"prod", "us-east-1.example"},
		{"prod", "us-gov-west-1"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, cluster, region string) {
		p := newEKSProvider(aws.Config{Region: "us-east-1"})
		args := &EKSAuthArgs{ClusterName: cluster, Region: region}
		if p.validateArgs(args) != nil {
			return
		}
		resolved := resolveRegion(region, "us-east-1")
		u := eksRequestURL(t, resolved, cluster)
		if u.Host != "eks."+resolved+".amazonaws.com" || u.EscapedPath() != "/clusters/"+cluster || u.RawQuery != "" {
			t.Errorf("accepted %q %q, request went to %s", cluster, region, u)
		}
	})
}

func FuzzAKSIdentifiersKeepTheRequestPath(f *testing.F) {
	for _, s := range [][3]string{
		{testSubscription, "rg-prod", "aks-1"},
		{testSubscription, "rg.(team)_x", "aks_1"},
		{testSubscription, "gruppe-ä", "aks"},
		{testSubscription, "..", "aks"},
		{testSubscription, "rg", ".."},
		{"..", "rg", "aks"},
		{testSubscription, "rg.", "aks"},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, sub, group, cluster string) {
		if (&AKSAuthArgs{SubscriptionID: sub, ResourceGroup: group, ClusterName: cluster}).validate() != nil {
			return
		}
		urls := aksRequestURLs(t, sub, group, cluster, http.StatusNotFound, `{}`)
		want := "/subscriptions/" + url.PathEscape(sub) + "/resourceGroups/" + url.PathEscape(group) +
			"/providers/Microsoft.ContainerService/managedClusters/" + url.PathEscape(cluster) +
			"/listClusterUserCredential"
		if len(urls) != 1 || urls[0].Host != "management.azure.com" || urls[0].EscapedPath() != want {
			t.Errorf("accepted %q %q %q, requests went to %v", sub, group, cluster, urls)
		}
	})
}
