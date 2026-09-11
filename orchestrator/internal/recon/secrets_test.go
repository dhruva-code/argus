package recon

import (
	"testing"
)

func TestCustomSecretDetectors(t *testing.T) {
	content := `
		const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
		const gh = "ghp_016C7e8b9A0d1E2f3G4h5I6j7K8l9M0n1O2p3";
		const slack = "xoxb-1234567890-abcdefghijklmnop";
		var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop";
		firebase: "https://myapp-1234.firebaseio.com",
	`
	found := customScan(content, "js:https://x/app.js")
	types := map[string]bool{}
	for _, s := range found {
		types[s.DetectorType] = true
		if s.DetectorType == "AWSAccessKeyID" && s.Value != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("AWS key value not carried unmasked: %q", s.Value)
		}
		if s.Fingerprint == "" {
			t.Error("empty fingerprint")
		}
	}
	for _, want := range []string{"AWSAccessKeyID", "GitHubToken", "SlackToken", "JWT", "FirebaseURL"} {
		if !types[want] {
			t.Errorf("missed detector %s (got %v)", want, types)
		}
	}
}

func TestSecretValueAndFingerprint(t *testing.T) {
	s := newSecret("AWS", "custom", "js:app.js:10", "AKIAIOSFODNN7EXAMPLE", false)
	if s.Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("value should be the full unmasked secret: %q", s.Value)
	}
	// same inputs -> same fingerprint (dedup key)
	s2 := newSecret("AWS", "custom", "js:app.js:10", "AKIAIOSFODNN7EXAMPLE", false)
	if s.Fingerprint != s2.Fingerprint {
		t.Error("fingerprint not deterministic")
	}
	s3 := newSecret("AWS", "custom", "js:other.js:5", "AKIAIOSFODNN7EXAMPLE", false)
	if s.Fingerprint == s3.Fingerprint {
		t.Error("fingerprint should include the location")
	}
}

func TestSensitivityClassifier(t *testing.T) {
	cases := []struct {
		path, sev string
	}{
		{"/.git/config", "critical"},
		{"/.env", "critical"},
		{"/backup.sql", "high"},
		{"/wp-config.php", "high"},
		{"/admin/", "medium"},
		{"/actuator/env", "high"},
		{"/.DS_Store", "low"},
		{"/about", "none"},
		{"/index.html", "none"},
	}
	for _, c := range cases {
		got, reason := classifySensitivity(c.path)
		if got != c.sev {
			t.Errorf("classifySensitivity(%q) = %q, want %q", c.path, got, c.sev)
		}
		if c.sev != "none" && reason == "" {
			t.Errorf("%q classified %s with no reason", c.path, got)
		}
	}
}

func TestSevForDetector(t *testing.T) {
	if sevFor("AWS", true) != "critical" {
		t.Error("verified secret should be critical")
	}
	if sevFor("PrivateKey", false) != "high" {
		t.Error("private key should be high")
	}
	if sevFor("GenericApiKey", false) != "medium" {
		t.Error("generic should be medium")
	}
}
