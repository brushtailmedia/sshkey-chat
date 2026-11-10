package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// TestFixtures_RealShapedIDs guards the fixture surfaces that drive the selected ID contracts.
// Keep negative inputs with a same-line malformed reason; never erase them.
func TestFixtures_RealShapedIDs(t *testing.T) {
	prefixes := map[string]bool{"usr_": true, "room_": true, "group_": true, "dm_": true, "msg_": true, "react_": true, "file_": true, "up_": true}
	for _, dir := range []string{".", "../store", "../../cmd/sshkey-server"} {
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("empty fixture scan: %s", dir)
		}
		for _, path := range files {
			base := filepath.Base(path)
			if base == "fixture_id_lint_test.go" || base == "fixture_lint_test.go" {
				continue
			}
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			issues, err := testutil.LintIDFixtures(path, source, prefixes)
			if err != nil {
				t.Fatal(err)
			}
			for _, issue := range issues {
				t.Errorf("%s:%d: %s", path, issue.Line, issue.Message)
			}
		}
	}
}
