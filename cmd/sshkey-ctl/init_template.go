package main

import _ "embed"

// defaultServerTOMLRecommended is the annotated full server.toml written by
// `sshkey-ctl init` unless --minimal is requested.
//
//go:embed default_server.toml
var defaultServerTOMLRecommended string
