//go:build ignore

// testbudget scores a `go test -json` run against the duration budgets in
// docs/testing/duration_budgets.txt: serial wall time per package, and a
// ceiling per top-level test. It is the scorer behind
// .github/scripts/check_test_durations.sh (nightly). Exit status is 1 when a
// package is over budget, when a test is over the ceiling without a
// "// slow: <reason>" comment on or above its func line, or when any test
// failed; both limits are scaled by -tolerance because CI runners are slower
// and noisier than a workstation.
//
//	go run .github/scripts/testbudget.go -budgets docs/testing/duration_budgets.txt -tolerance 2 run.json
//
// Standard library only; kept out of the module's packages by the ignore tag.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type event struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
}

type budgets struct {
	pkgDefault float64            // seconds for any package not listed
	test       float64            // seconds for one top-level test
	pkg        map[string]float64 // "./internal/server" -> seconds
}

func (b budgets) forPackage(rel string) float64 {
	if v, ok := b.pkg[rel]; ok {
		return v
	}
	return b.pkgDefault
}

type testKey struct{ pkg, name string }

func main() {
	budgetPath := flag.String("budgets", "docs/testing/duration_budgets.txt", "budget file")
	tolerance := flag.Float64("tolerance", 2, "fail only past this factor over a budget")
	root := flag.String("root", ".", "module root (holds go.mod)")
	flag.Parse()

	b, err := readBudgets(*budgetPath)
	if err != nil {
		fail("duration guard: %v", err)
	}
	module, err := moduleName(*root)
	if err != nil {
		fail("duration guard: %v", err)
	}

	in := os.Stdin
	if flag.NArg() > 0 {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			fail("duration guard: %v", err)
		}
		defer f.Close()
		in = f
	}

	pkgTime := map[string]float64{}
	pkgState := map[string]string{}
	testTime := map[testKey]float64{}
	failedTests := 0

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<26) // -json lines carry test output and can be long
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue // build output and other non-event lines
		}
		var ev event
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
		default:
			continue
		}
		if ev.Test == "" {
			pkgTime[ev.Package] = ev.Elapsed
			pkgState[ev.Package] = ev.Action
			continue
		}
		if ev.Action == "fail" {
			failedTests++
		}
		if strings.Contains(ev.Test, "/") {
			continue // subtests are inside their parent's time
		}
		testTime[testKey{ev.Package, ev.Test}] = ev.Elapsed
	}
	if err := sc.Err(); err != nil {
		fail("duration guard: read: %v", err)
	}

	var violations []string

	pkgs := make([]string, 0, len(pkgTime))
	for p := range pkgTime {
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgTime[pkgs[i]] > pkgTime[pkgs[j]] })
	total := 0.0
	fmt.Printf("%8s %7s  %-5s %s\n", "wall", "budget", "state", "package")
	for _, p := range pkgs {
		rel := relPath(module, p)
		budget := b.forPackage(rel)
		total += pkgTime[p]
		fmt.Printf("%7.2fs %6.0fs  %-5s %s\n", pkgTime[p], budget, pkgState[p], rel)
		if limit := budget * *tolerance; pkgTime[p] > limit {
			violations = append(violations, fmt.Sprintf("package %s took %.1fs; budget %.0fs x%.1f = %.0fs",
				rel, pkgTime[p], budget, *tolerance, limit))
		}
	}
	fmt.Printf("total %.1fs across %d packages (serial, -p 1)\n", total, len(pkgs))

	keys := make([]testKey, 0, len(testTime))
	for k := range testTime {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return testTime[keys[i]] > testTime[keys[j]] })
	testLimit := b.test * *tolerance
	for _, k := range keys {
		if testTime[k] <= testLimit {
			break
		}
		rel := relPath(module, k.pkg)
		if hasSlowMarker(filepath.Join(*root, rel), k.name) {
			fmt.Printf("slow, marked: %6.2fs %s %s\n", testTime[k], rel, k.name)
			continue
		}
		violations = append(violations, fmt.Sprintf("test %s %s took %.1fs; ceiling %.0fs x%.1f = %.0fs — wait on a signal, or add a \"// slow: <reason>\" comment above the func",
			rel, k.name, testTime[k], b.test, *tolerance, testLimit))
	}

	if failedTests > 0 {
		violations = append(violations, fmt.Sprintf("%d test(s) failed in this run", failedTests))
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(os.Stderr, "duration guard:", v)
		}
		os.Exit(1)
	}
	fmt.Printf("duration guard: PASS (%d packages within budget; no unmarked test over %.0fs)\n", len(pkgs), testLimit)
}

// readBudgets parses "key | seconds | rationale" lines. Keys are "default",
// "test", or a package path relative to the module root ("./internal/server").
func readBudgets(path string) (budgets, error) {
	b := budgets{pkg: map[string]float64{}}
	f, err := os.Open(path)
	if err != nil {
		return b, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		parts := strings.Split(text, "|")
		if len(parts) < 2 {
			return b, fmt.Errorf("%s:%d: want \"key | seconds | rationale\"", path, line)
		}
		key := strings.TrimSpace(parts[0])
		secs, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil || secs <= 0 {
			return b, fmt.Errorf("%s:%d: bad seconds %q", path, line, strings.TrimSpace(parts[1]))
		}
		switch key {
		case "default":
			b.pkgDefault = secs
		case "test":
			b.test = secs
		default:
			b.pkg[key] = secs
		}
	}
	if err := sc.Err(); err != nil {
		return b, err
	}
	if b.pkgDefault == 0 || b.test == 0 {
		return b, fmt.Errorf("%s: needs both a \"default\" and a \"test\" line", path)
	}
	return b, nil
}

func moduleName(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	return "", fmt.Errorf("no module line in %s", filepath.Join(root, "go.mod"))
}

// relPath turns an import path into the budget file's "./dir" form.
func relPath(module, pkg string) string {
	if pkg == module {
		return "."
	}
	return "./" + strings.TrimPrefix(pkg, module+"/")
}

// hasSlowMarker reports whether the test's func line, or a run of comment
// lines directly above it, contains "slow:".
func hasSlowMarker(dir, test string) bool {
	files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
	prefix := "func " + test + "("
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, l := range lines {
			if !strings.HasPrefix(l, prefix) {
				continue
			}
			if strings.Contains(l, "slow:") {
				return true
			}
			for j := i - 1; j >= 0; j-- {
				c := strings.TrimSpace(lines[j])
				if !strings.HasPrefix(c, "//") {
					break
				}
				if strings.Contains(c, "slow:") {
					return true
				}
			}
			return false
		}
	}
	return false
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
