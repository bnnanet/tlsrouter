package ipgate

import (
	"context"
	"os"
	"testing"
)

func TestNewDomainBlocklist(t *testing.T) {
	// Create a temporary blacklist file
	content := `# Test blacklist
blocked.example.com
another.bad.com
UPPERCASE.COM
*.wildcard.com

`
	tmpFile, err := os.CreateTemp("", "blacklist-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	ctx := context.Background()
	bl, err := NewDomainBlocklist(ctx, tmpFile.Name())
	if err != nil {
		t.Fatalf("NewDomainBlocklist: %v", err)
	}

	// Check Contains
	tests := []struct {
		domain string
		want   bool
	}{
		{"blocked.example.com", true},
		{"Blocked.Example.Com", true}, // case insensitive
		{"another.bad.com", true},
		{"uppercase.com", true},
		{"UPPERCASE.COM", true},
		{"notblocked.com", false},
		{"blocked.example.com.evil.com", false},
		// Wildcard forms: *.wildcard.com, .wildcard.com, wildcard.com all match
		{"*.wildcard.com", true},
		{".wildcard.com", true},
		{"wildcard.com", true},
		{"WILDCARD.COM", true},
		{"sub.wildcard.com", false},
	}

	for _, tc := range tests {
		got := bl.Contains(tc.domain)
		if got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}

	// Check Domains() returns non-empty
	doms := bl.Domains()
	if len(doms) != 4 {
		t.Errorf("Domains() returned %d entries, want 4", len(doms))
	}
}

func TestNewDomainBlocklist_Nil(t *testing.T) {
	bl, err := NewDomainBlocklist(context.Background(), "")
	if err != nil {
		t.Fatal("expected nil, nil for empty path")
	}
	if bl != nil {
		t.Error("expected nil blocklist for empty path")
	}

	// Nil receiver should be safe
	if bl.Contains("anything.com") {
		t.Error("nil blocklist should not contain anything")
	}
	if bl.Domains() != nil {
		t.Error("nil blocklist Domains() should return nil")
	}
}
