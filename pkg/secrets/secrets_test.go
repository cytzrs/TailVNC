package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromEnvOrFile(t *testing.T) {
	// Env wins.
	t.Setenv("TAILVNC_AUTH_PASS", "from-env")
	if got := FromEnvOrFile("TAILVNC_AUTH_PASS", ""); got != "from-env" {
		t.Fatalf("env: got %q", got)
	}

	// File fallback when env unset.
	dir := t.TempDir()
	p := filepath.Join(dir, "pass")
	if err := os.WriteFile(p, []byte("from-file"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAILVNC_AUTH_PASS", "")
	if got := FromEnvOrFile("TAILVNC_AUTH_PASS", p); got != "from-file" {
		t.Fatalf("file: got %q", got)
	}

	// Neither -> empty.
	if got := FromEnvOrFile("TAILVNC_AUTH_PASS", ""); got != "" {
		t.Fatalf("empty: got %q", got)
	}
}
