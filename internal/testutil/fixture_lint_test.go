package testutil_test

import (
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

func TestFixtureLint_SourceFormsAndExemptions(t *testing.T) {
	cases := []struct {
		name, body string
		bad        bool
	}{
		{"typed builder", `_ = protocol.Send{Room:testutil.RoomID("a")}`, false},
		{"short", `_ = protocol.Send{Room:"room_short"}`, true},
		{"wrong prefix", `_ = protocol.Send{Room:"usr_AAAAAAAAAAAAAAAAAAAAA"}`, true},
		{"unprefixed role", `_ = protocol.AddToGroup{User:"alice"}`, true},
		{"display name", `_ = store.User{DisplayName:"alice"}`, false},
		{"protocol type", `_ = protocol.GroupCreated{Type:"group_created"}`, false},
		{"SQL table", `table := "file_uploads"; _ = table`, false},
		{"JSON", "_ = `{" + `"type":"send","room":"room_bad"` + "}`", true},
		{"format", `_ = fmt.Sprintf("{\"room\":\"%s\"}",testutil.RoomID("a"))`, false},
		{"concat", `_ = protocol.Send{Room:"room_"+strings.Repeat("A",21)}`, false},
		{"unknown format", `_ = protocol.Send{Room:fmt.Sprintf("room_%d",i)}`, true},
		{"reason", `_ = protocol.Send{Room:"room_bad"} // malformed: short room rejection`, false},
		{"bare marker", `_ = protocol.Send{Room:"room_bad"} // malformed:`, true},
		{"other line", "// malformed: not on the fixture line\n_ = protocol.Send{Room:\"room_bad\"}", true},
		{"unrelated comment", `_ = protocol.Send{Room:"room_bad"} // ordinary fixture`, true},
	}
	cases = append(cases, struct {
		name, body string
		bad        bool
	}{"SSH login name", `_ = ssh.ClientConfig{User:"sshkey"}`, false}, struct {
		name, body string
		bad        bool
	}{"elided message row", `_ = []protocol.Message{{ID:"msg_short"}}`, true})

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			source := []byte("package p\nfunc f(){\n" + tt.body + "\n}\n")
			issues, err := testutil.LintIDFixtures("sample.go", source, map[string]bool{"room_": true, "usr_": true, "msg_": true})
			if err != nil {
				t.Fatal(err)
			}
			if (len(issues) > 0) != tt.bad {
				t.Fatalf("issues=%v; want bad=%v", issues, tt.bad)
			}
		})
	}
	if _, err := testutil.LintIDFixtures("bad.go", []byte("package {"), nil); err == nil {
		t.Fatal("parse failure was ignored")
	}
}

func TestFixtureLint_DynamicTemplatesKeepLiteralChecks(t *testing.T) {
	for _, tt := range []struct {
		body string
		bad  bool
	}{
		{`_ = fmt.Sprintf("{\"room\":\"%s\"}",roomID)`, false},
		{`_ = fmt.Sprintf("{\"room\":\"%s\",\"user\":\"alice\"}",roomID)`, true},
		{`_ = protocol.Read{LastRead:""}`, false},
		{`_ = protocol.SetProfile{AvatarID:""}`, false},
	} {
		issues, err := testutil.LintIDFixtures("sample.go", []byte("package p\nfunc f(){"+tt.body+"\n}"), map[string]bool{"room_": true, "usr_": true, "msg_": true, "file_": true})
		if err != nil {
			t.Fatal(err)
		}
		if (len(issues) > 0) != tt.bad {
			t.Fatalf("body=%s issues=%v want bad=%v", tt.body, issues, tt.bad)
		}
	}
}
