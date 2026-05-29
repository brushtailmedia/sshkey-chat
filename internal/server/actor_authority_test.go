package server

import (
	"reflect"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestInboundFramesCarryNoClientActorField locks the actor-authority invariant
// behind audit finding S1. The server is actor-authoritative: every actor field
// (from / deleted_by / pinned_by / reaction user) is stamped server-side from
// the authenticated session (c.UserID), and the inbound client→server frames
// must therefore carry NO actor/sender field that a client could spoof. If
// someone later adds a From/Sender/User/DeletedBy/PinnedBy/Author/Actor field to
// one of these inbound frames, the server could begin trusting a client-supplied
// actor (reintroducing impersonation), and this test fails — pointing them at
// the audit before they ship it.
//
// NOTE: this guards the INBOUND frames only. The server→client OUTPUT structs
// (Edited, Deleted, Reaction, Pinned, ...) legitimately carry server-stamped
// actor fields and are intentionally excluded.
func TestInboundFramesCarryNoClientActorField(t *testing.T) {
	bannedActorField := map[string]bool{
		"from":      true,
		"sender":    true,
		"user":      true,
		"author":    true,
		"deletedby": true,
		"pinnedby":  true,
		"actor":     true,
		"reactedby": true,
	}

	inbound := []any{
		protocol.Send{}, protocol.SendGroup{}, protocol.SendDM{},
		protocol.Edit{}, protocol.EditGroup{}, protocol.EditDM{},
		protocol.Delete{},
		protocol.React{}, protocol.Unreact{},
		protocol.Pin{}, protocol.Unpin{},
	}

	for _, frame := range inbound {
		ty := reflect.TypeOf(frame)
		for i := 0; i < ty.NumField(); i++ {
			name := ty.Field(i).Name
			if bannedActorField[strings.ToLower(name)] {
				t.Errorf("%s.%s: inbound frames must carry no client-settable actor field — "+
					"the server stamps the actor from the authenticated session (audit S1)",
					ty.Name(), name)
			}
		}
	}
}
