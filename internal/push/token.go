package push

const tokenLogPrefixLen = 8

// tokenLogValue returns a bounded token preview safe for logs.
// It never panics on short tokens and avoids logging full token values.
func tokenLogValue(token string) string {
	if token == "" {
		return "<empty>"
	}
	n := len(token)
	if n > tokenLogPrefixLen {
		n = tokenLogPrefixLen
	}
	return token[:n] + "..."
}
