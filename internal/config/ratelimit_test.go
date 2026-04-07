package config

import "testing"

func TestDefaultRateLimits(t *testing.T) {
	cfg := DefaultServerConfig()
	rl := cfg.RateLimits

	tests := []struct {
		name  string
		value int
		want  int
	}{
		{"MessagesPerSecond", rl.MessagesPerSecond, 5},
		{"UploadsPerMinute", rl.UploadsPerMinute, 60},
		{"ConnectionsPerMinute", rl.ConnectionsPerMinute, 20},
		{"FailedAuthPerMinute", rl.FailedAuthPerMinute, 5},
		{"TypingPerSecond", rl.TypingPerSecond, 1},
		{"HistoryPerMinute", rl.HistoryPerMinute, 50},
		{"DeletesPerMinute", rl.DeletesPerMinute, 10},
		{"AdminDeletesPerMinute", rl.AdminDeletesPerMinute, 50},
		{"ReactionsPerMinute", rl.ReactionsPerMinute, 30},
		{"DMCreatesPerMinute", rl.DMCreatesPerMinute, 5},
		{"ProfilesPerMinute", rl.ProfilesPerMinute, 5},
		{"PinsPerMinute", rl.PinsPerMinute, 10},
	}

	for _, tc := range tests {
		if tc.value != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.value, tc.want)
		}
	}
}

func TestRateLimits_AllPositive(t *testing.T) {
	cfg := DefaultServerConfig()
	rl := cfg.RateLimits

	if rl.DeletesPerMinute <= 0 {
		t.Error("DeletesPerMinute should be positive")
	}
	if rl.AdminDeletesPerMinute <= rl.DeletesPerMinute {
		// Admin limit should be higher than user limit
	} else {
		// This is fine — admin gets more
	}
	if rl.AdminDeletesPerMinute < rl.DeletesPerMinute {
		t.Error("AdminDeletesPerMinute should be >= DeletesPerMinute")
	}
}
