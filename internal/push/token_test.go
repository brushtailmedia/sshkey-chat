package push

import "testing"

func TestTokenLogValue_BoundedAndSafe(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "<empty>"},
		{name: "short", in: "abc", want: "abc..."},
		{name: "exact8", in: "12345678", want: "12345678..."},
		{name: "long", in: "1234567890", want: "12345678..."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tokenLogValue(tc.in)
			if got != tc.want {
				t.Fatalf("tokenLogValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
