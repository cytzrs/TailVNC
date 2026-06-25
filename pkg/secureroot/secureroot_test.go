package secureroot

import "testing"

func TestIsInSecureDir(t *testing.T) {
	// Roots are admin-writable AND not user-writable: System32, not bare SystemRoot
	// (bare SystemRoot would let C:\Windows\Temp through).
	roots := []string{`C:\Program Files`, `C:\Program Files (x86)`, `C:\Windows\System32`}
	cases := []struct {
		name string
		exe  string
		want bool
	}{
		{"under program files", `C:\Program Files\TailVNC\TailVNC.exe`, true},
		{"case-insensitive root", `c:\program files\tailvnc\tailvnc.exe`, true},
		{"under system32", `C:\Windows\System32\TailVNC.exe`, true},
		{"temp rejected (not under system32)", `C:\Windows\Temp\TailVNC.exe`, false},
		{"bare windows rejected", `C:\Windows\TailVNC.exe`, false},
		{"user profile rejected", `C:\Users\bob\Downloads\TailVNC.exe`, false},
		{"public rejected", `C:\Users\Public\TailVNC.exe`, false},
		{"relative rejected", `TailVNC.exe`, false},
		{"empty rejected", ``, false},
	}
	for _, c := range cases {
		if got := IsInSecureDir(c.exe, roots); got != c.want {
			t.Errorf("%s: IsInSecureDir(%q)=%v, want %v", c.name, c.exe, got, c.want)
		}
	}
}
