package server

// TestFixtures_NoDummyWrappedKeys is a lint over the test sources that
// exercise the server's frame checks: every wrapped_keys value written as a
// literal must be real-size. A production wrap is 124 base64 characters,
// and for months every fixture used "wa", "k" or "wkey" — so no test frame
// was ever near 16 KB and the bare frame check that stopped a group at the
// member cap from sending went unseen. Fixtures use
// testutil.WrappedKey(seed) instead.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// minWrappedKeyChars is the shortest literal the lint accepts: shorter than
// a real wrap (124) to leave room for other real encodings, far longer than
// any dummy.
const minWrappedKeyChars = 100

// fixtureLintDirs are the packages whose tests drive frames through the
// server's size checks: this package's handler tests and the end-to-end
// tests over SSH. Store and protocol tests never reach a frame check (and
// the protocol fuzz corpus is deliberately malformed), so they are not
// linted.
var fixtureLintDirs = []string{".", filepath.Join("..", "..", "cmd", "sshkey-server")}

var (
	rawWrappedKeysRe = regexp.MustCompile(`"wrapped_keys"\s*:\s*\{([^}]*)\}`)
	rawPairRe        = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)"`)
)

func TestFixtures_NoDummyWrappedKeys(t *testing.T) {
	var bad []string
	for _, dir := range fixtureLintDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no test files under %s — lint scope is wrong", dir)
		}
		for _, f := range files {
			if filepath.Base(f) == "fixture_lint_test.go" {
				continue
			}
			bad = append(bad, lintWrappedKeyLiterals(t, f)...)
		}
	}
	if len(bad) > 0 {
		t.Errorf("%d dummy wrapped_keys fixture(s); use testutil.WrappedKey(seed) (%d+ characters):\n  %s",
			len(bad), minWrappedKeyChars, strings.Join(bad, "\n  "))
	}
}

// lintWrappedKeyLiterals reports every string literal shorter than
// minWrappedKeyChars used as a value in a `WrappedKeys: map[string]string{…}`
// composite literal, or as a value inside a raw-JSON `"wrapped_keys":{…}`
// object within one string literal. A value containing a format verb (%)
// is a template, not a fixture, and is skipped.
func lintWrappedKeyLiterals(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var bad []string
	report := func(pos token.Pos, value string) {
		bad = append(bad, fmt.Sprintf("%s: wrapped_keys value %q is %d characters", fset.Position(pos), value, len(value)))
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.KeyValueExpr:
			key, ok := v.Key.(*ast.Ident)
			if !ok || key.Name != "WrappedKeys" {
				return true
			}
			lit, ok := v.Value.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if s, err := strconv.Unquote(bl.Value); err == nil && len(s) < minWrappedKeyChars {
						report(bl.Pos(), s)
					}
				}
			}
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(v.Value)
			if err != nil || !strings.Contains(s, `"wrapped_keys"`) {
				return true
			}
			for _, obj := range rawWrappedKeysRe.FindAllStringSubmatch(s, -1) {
				for _, pair := range rawPairRe.FindAllStringSubmatch(obj[1], -1) {
					val := pair[2]
					if strings.Contains(val, "%") {
						continue
					}
					if len(val) < minWrappedKeyChars {
						report(v.Pos(), val)
					}
				}
			}
		}
		return true
	})
	return bad
}
