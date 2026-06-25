// Package secureroot guards the SYSTEM service's re-exec of itself (SEC-4).
// A local non-admin who can write the binary's directory can swap the file and
// get SYSTEM code execution on the next agent spawn. M1 mitigates by allowing
// re-exec only when the executable lives under an admin-writable root. The
// fuller DACL-based check is deferred to M3.
//
// NOTE: the caller should pass roots that are admin-writable AND not
// user-writable (e.g. %ProgramFiles%, %SystemRoot%\System32). A bare
// %SystemRoot% would let C:\Windows\Temp through, so it is intentionally
// narrowed to System32 here.
package secureroot

import (
	"path"
	"strings"
)

// IsInSecureDir reports whether exePath's containing directory is at or under
// one of secureRoots. Comparison is case-insensitive and separator-agnostic
// (backslashes normalized to forward slashes) so the package is unit-testable
// on non-Windows. A relative or driveless path is never secure.
func IsInSecureDir(exePath string, secureRoots []string) bool {
	norm := func(p string) string {
		return strings.ToLower(path.Clean(strings.ReplaceAll(p, "\\", "/")))
	}
	isAbs := func(p string) bool {
		return strings.HasPrefix(p, "/") || (len(p) >= 3 && p[1] == ':' && p[2] == '/')
	}
	dir := norm(exePath)
	if exePath == "" || !isAbs(dir) {
		return false
	}
	for _, root := range secureRoots {
		r := norm(root)
		if dir == r || strings.HasPrefix(dir, r+"/") {
			return true
		}
	}
	return false
}
