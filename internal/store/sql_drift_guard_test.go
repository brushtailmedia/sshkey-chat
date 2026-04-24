package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestSQLDriftGuard_NoNewFmtSprintfSQL(t *testing.T) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	type finding struct {
		path   string
		line   int
		format string
	}
	var findings []finding

	walkErr := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Sprintf" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "fmt" {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			format, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if !looksLikeSQL(format) {
				return true
			}
			if allowedSQLSprintf(path, format) {
				return true
			}
			pos := fset.Position(call.Pos())
			findings = append(findings, finding{
				path:   path,
				line:   pos.Line,
				format: format,
			})
			return true
		})

		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk repo for SQL drift guard: %v", walkErr)
	}

	if len(findings) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("found disallowed fmt.Sprintf SQL format strings:\n")
	for _, f := range findings {
		b.WriteString(" - ")
		b.WriteString(f.path)
		b.WriteString(":")
		b.WriteString(strconv.Itoa(f.line))
		b.WriteString(" -> ")
		b.WriteString(strconv.Quote(f.format))
		b.WriteString("\n")
	}
	b.WriteString("If intentional, update docs/security/sql_audit.md and this allowlist.")
	t.Fatal(b.String())
}

func looksLikeSQL(s string) bool {
	u := strings.ToUpper(s)
	keywords := []string{
		"SELECT ",
		"INSERT INTO ",
		"UPDATE ",
		"DELETE FROM ",
		"CREATE TABLE ",
		"ALTER TABLE ",
		"DROP TABLE ",
		" WHERE ",
		" FROM ",
		" SET ",
	}
	for _, kw := range keywords {
		if strings.Contains(u, kw) {
			return true
		}
	}
	return false
}

func allowedSQLSprintf(path, format string) bool {
	p := filepath.ToSlash(path)
	if strings.HasSuffix(p, "/internal/store/direct_messages.go") &&
		strings.Contains(format, "UPDATE direct_messages SET %s = ? WHERE id = ? AND %s < ?") {
		return true
	}
	if strings.HasSuffix(p, "/internal/server/failing_store_test.go") {
		return true
	}
	return false
}
