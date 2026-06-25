// Package secrets reads sensitive configuration from environment variables or
// protected files — never from process argv (which leaks into `ps`, build
// logs, and shell history).
package secrets

import (
	"os"
	"strings"
)

// FromEnvOrFile returns the value of envVar if set and non-empty; otherwise
// the trimmed contents of path if it exists; otherwise the empty string.
func FromEnvOrFile(envVar, path string) string {
	if v := strings.TrimSpace(os.Getenv(envVar)); v != "" {
		return v
	}
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
