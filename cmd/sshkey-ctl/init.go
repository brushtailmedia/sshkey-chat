package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

const (
	defaultBindAddr  = "0.0.0.0"
	defaultPort      = 2222
	defaultConfigDir = "/etc/sshkey-chat"
	defaultDataDir   = "/var/sshkey-chat"

	initProfileDev    = "dev"
	initProfileDocker = "docker"
	initProfileProd   = "prod"
)

type initOptions struct {
	configDir string
	dataDir   string
	bind      string
	port      int
	profile   string

	minimalConfig bool

	createStarterRooms bool
	starterRooms       []string
	markStarterDefault bool
}

type initProfileDefaults struct {
	configDir string
	dataDir   string
	bind      string
	port      int
}

func cmdInit(configDir, dataDir string, args []string) error {
	tty := term.IsTerminal(int(os.Stdin.Fd()))
	return cmdInitWithIO(configDir, dataDir, args, os.Stdin, os.Stdout, tty)
}

func cmdInitWithIO(configDir, dataDir string, args []string, in io.Reader, out io.Writer, tty bool) error {
	opts := initOptions{
		configDir:          configDir,
		dataDir:            dataDir,
		profile:            initProfileProd,
		createStarterRooms: true,
		starterRooms:       []string{"general", "support"},
		markStarterDefault: true,
	}

	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dockerPreset bool
	var profileName string
	var minimal bool
	var yes bool
	var noStarterRooms bool
	var noDefaultStarter bool
	var starterCSV string
	var bind string
	var port int
	var configOverride string
	var dataOverride string
	fs.BoolVar(&dockerPreset, "docker", false, "use docker defaults")
	fs.StringVar(&profileName, "profile", initProfileProd, "init profile: dev|docker|prod")
	fs.BoolVar(&minimal, "minimal", false, "write a minimal server.toml instead of the recommended full template")
	fs.BoolVar(&yes, "yes", false, "non-interactive mode")
	fs.BoolVar(&noStarterRooms, "no-starter-rooms", false, "do not create starter rooms")
	fs.BoolVar(&noDefaultStarter, "no-default-starter-rooms", false, "do not mark starter rooms as default")
	fs.StringVar(&starterCSV, "starter-rooms", "", "comma-separated starter rooms")
	fs.StringVar(&bind, "bind", "", "bind address")
	fs.IntVar(&port, "port", 0, "port")
	fs.StringVar(&configOverride, "config", "", "config directory")
	fs.StringVar(&dataOverride, "data", "", "data directory")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("usage: init [--profile dev|docker|prod] [--minimal] [--docker] [--yes] [--config DIR] [--data DIR] [--bind ADDR] [--port N]")
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("usage: init [--profile dev|docker|prod] [--minimal] [--docker] [--yes] [--config DIR] [--data DIR] [--bind ADDR] [--port N]")
	}

	profileFlagSet := flagWasSet(fs, "profile")
	if dockerPreset {
		if profileFlagSet && !strings.EqualFold(strings.TrimSpace(profileName), initProfileDocker) {
			return fmt.Errorf("--docker cannot be combined with --profile=%q (use --profile docker or omit --profile)", profileName)
		}
		profileName = initProfileDocker
	}

	profileName, err := normalizeInitProfile(profileName)
	if err != nil {
		return err
	}
	opts.profile = profileName
	opts.minimalConfig = minimal
	applyInitProfileDefaults(&opts, profileName, configDir, dataDir)
	if configOverride != "" {
		opts.configDir = configOverride
	}
	if dataOverride != "" {
		opts.dataDir = dataOverride
	}
	if bind != "" {
		opts.bind = strings.TrimSpace(bind)
	}
	if flagWasSet(fs, "port") {
		opts.port = port
	}
	if noStarterRooms {
		opts.createStarterRooms = false
	}
	if noDefaultStarter {
		opts.markStarterDefault = false
	}
	if starterCSV != "" {
		rooms, err := parseStarterRooms(starterCSV)
		if err != nil {
			return err
		}
		opts.starterRooms = rooms
	}

	if yes {
		return runInit(opts, out)
	}
	if !tty {
		return fmt.Errorf("init requires an interactive terminal unless --yes is set")
	}

	if err := promptInitOptions(in, out, &opts); err != nil {
		return err
	}
	return runInit(opts, out)
}

func promptInitOptions(in io.Reader, out io.Writer, opts *initOptions) error {
	reader := bufio.NewReader(in)
	fmt.Fprintln(out, "Press Enter to accept defaults shown in [brackets].")

	var err error
	if opts.configDir, err = promptString(reader, out, "Config directory", opts.configDir); err != nil {
		return err
	}
	if opts.dataDir, err = promptString(reader, out, "Data directory", opts.dataDir); err != nil {
		return err
	}
	if opts.bind, err = promptString(reader, out, "Bind address", opts.bind); err != nil {
		return err
	}
	if opts.port, err = promptPort(reader, out, opts.port); err != nil {
		return err
	}

	createStarter, err := promptInitYesNo(reader, out, "Create starter rooms", opts.createStarterRooms)
	if err != nil {
		return err
	}
	opts.createStarterRooms = createStarter
	if !opts.createStarterRooms {
		return nil
	}

	starterDefault := strings.Join(opts.starterRooms, ",")
	starterRaw, err := promptString(reader, out, "Starter rooms", starterDefault)
	if err != nil {
		return err
	}
	rooms, err := parseStarterRooms(starterRaw)
	if err != nil {
		return err
	}
	opts.starterRooms = rooms

	opts.markStarterDefault, err = promptInitYesNo(reader, out, "Mark starter rooms as default auto-join rooms", opts.markStarterDefault)
	return err
}

func promptString(r *bufio.Reader, out io.Writer, label, def string) (string, error) {
	for {
		fmt.Fprintf(out, "%s [%s]: ", label, def)
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			line = def
		}
		if strings.TrimSpace(line) == "" {
			if err == io.EOF {
				return "", fmt.Errorf("empty value for %s", label)
			}
			fmt.Fprintf(out, "%s cannot be empty.\n", label)
			continue
		}
		return line, nil
	}
}

func promptPort(r *bufio.Reader, out io.Writer, def int) (int, error) {
	for {
		fmt.Fprintf(out, "Port [%d]: ", def)
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		port, convErr := strconv.Atoi(line)
		if convErr != nil || port < 1 || port > 65535 {
			fmt.Fprintln(out, "Port must be an integer between 1 and 65535.")
			if err == io.EOF {
				return 0, fmt.Errorf("invalid port %q", line)
			}
			continue
		}
		return port, nil
	}
}

func promptInitYesNo(r *bufio.Reader, out io.Writer, label string, defYes bool) (bool, error) {
	def := "Y/n"
	if !defYes {
		def = "y/N"
	}
	for {
		fmt.Fprintf(out, "%s [%s]: ", label, def)
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		line = strings.TrimSpace(strings.ToLower(line))
		if line == "" {
			return defYes, nil
		}
		switch line {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(out, "Please enter y or n.")
			if err == io.EOF {
				return false, fmt.Errorf("invalid yes/no answer %q", line)
			}
		}
	}
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func normalizeInitProfile(raw string) (string, error) {
	profile := strings.ToLower(strings.TrimSpace(raw))
	switch profile {
	case "":
		return initProfileProd, nil
	case initProfileDev, initProfileDocker, initProfileProd:
		return profile, nil
	default:
		return "", fmt.Errorf("invalid --profile %q (valid: dev, docker, prod)", raw)
	}
}

func applyInitProfileDefaults(opts *initOptions, profile, baseConfigDir, baseDataDir string) {
	defs := initProfileValues(profile)
	opts.bind = defs.bind
	opts.port = defs.port

	if strings.TrimSpace(baseConfigDir) == "" || strings.TrimSpace(baseConfigDir) == defaultConfigDir {
		opts.configDir = defs.configDir
	}
	if strings.TrimSpace(baseDataDir) == "" || strings.TrimSpace(baseDataDir) == defaultDataDir {
		opts.dataDir = defs.dataDir
	}
}

func initProfileValues(profile string) initProfileDefaults {
	switch profile {
	case initProfileDev:
		home, err := os.UserHomeDir()
		if err == nil {
			home = strings.TrimSpace(home)
		}
		if home != "" {
			return initProfileDefaults{
				configDir: filepath.Join(home, ".sshkey-chat", "config"),
				dataDir:   filepath.Join(home, ".sshkey-chat", "data"),
				bind:      "127.0.0.1",
				port:      defaultPort,
			}
		}
		// If HOME is unavailable, fall back to production paths but keep the
		// local-only loopback bind expected from the dev profile.
		return initProfileDefaults{
			configDir: defaultConfigDir,
			dataDir:   defaultDataDir,
			bind:      "127.0.0.1",
			port:      defaultPort,
		}
	case initProfileDocker:
		return initProfileDefaults{
			configDir: defaultConfigDir,
			dataDir:   defaultDataDir,
			bind:      defaultBindAddr,
			port:      defaultPort,
		}
	case initProfileProd:
		fallthrough
	default:
		return initProfileDefaults{
			configDir: defaultConfigDir,
			dataDir:   defaultDataDir,
			bind:      defaultBindAddr,
			port:      defaultPort,
		}
	}
}

func parseStarterRooms(csv string) ([]string, error) {
	parts := strings.Split(csv, ",")
	var out []string
	seen := map[string]bool{}
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("starter rooms list cannot be empty")
	}
	return out, nil
}

func runInit(opts initOptions, out io.Writer) error {
	opts.configDir = strings.TrimSpace(opts.configDir)
	opts.dataDir = strings.TrimSpace(opts.dataDir)
	opts.bind = strings.TrimSpace(opts.bind)
	if opts.configDir == "" || opts.dataDir == "" {
		return fmt.Errorf("config and data directories must be non-empty")
	}
	if opts.bind == "" {
		return fmt.Errorf("bind address must be non-empty")
	}
	if opts.port < 1 || opts.port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	if err := os.MkdirAll(opts.configDir, 0750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.MkdirAll(opts.dataDir, 0750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	serverPath := filepath.Join(opts.configDir, "server.toml")
	if _, err := os.Stat(serverPath); err == nil {
		fmt.Fprintf(out, "server.toml already exists at %s, keeping existing file.\n", serverPath)
	} else if os.IsNotExist(err) {
		if err := writeInitServerToml(serverPath, opts.bind, opts.port, opts.dataDir, opts.profile, opts.minimalConfig); err != nil {
			return err
		}
		fmt.Fprintf(out, "Wrote %s.\n", serverPath)
	} else {
		return fmt.Errorf("stat %s: %w", serverPath, err)
	}

	st, err := store.Open(opts.dataDir)
	if err != nil {
		return fmt.Errorf("initialize store: %w", err)
	}
	defer st.Close()

	createdRooms := 0
	defaultFlagged := 0
	if opts.createStarterRooms {
		for _, roomName := range opts.starterRooms {
			room, err := st.GetRoomByDisplayName(roomName)
			if err != nil {
				return fmt.Errorf("lookup room %q: %w", roomName, err)
			}
			roomID := ""
			if room == nil {
				roomID = store.GenerateRoomID()
				if _, err := st.RoomsDB().Exec(`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`, roomID, roomName, ""); err != nil {
					return fmt.Errorf("create starter room %q: %w", roomName, err)
				}
				createdRooms++
			} else {
				roomID = room.ID
			}

			if opts.markStarterDefault {
				if err := st.SetRoomIsDefault(roomID, true); err != nil {
					return fmt.Errorf("mark starter room %q default: %w", roomName, err)
				}
				defaultFlagged++
			}
		}
	}

	fmt.Fprintln(out, "Initialization complete.")
	fmt.Fprintf(out, "  Config dir: %s\n", opts.configDir)
	fmt.Fprintf(out, "  Data dir:   %s\n", opts.dataDir)
	fmt.Fprintf(out, "  Bind:       %s\n", opts.bind)
	fmt.Fprintf(out, "  Port:       %d\n", opts.port)
	fmt.Fprintf(out, "  Profile:    %s\n", opts.profile)
	if opts.minimalConfig {
		fmt.Fprintln(out, "  server.toml mode: minimal (--minimal)")
	} else {
		fmt.Fprintln(out, "  server.toml mode: recommended template (default)")
	}
	if opts.createStarterRooms {
		fmt.Fprintf(out, "  Starter rooms ensured: %d (created this run: %d)\n", len(opts.starterRooms), createdRooms)
		if opts.markStarterDefault {
			fmt.Fprintf(out, "  Starter rooms default-flagged: %d\n", defaultFlagged)
		}
	}
	return nil
}

func writeInitServerToml(path, bind string, port int, dataDir, profile string, minimal bool) error {
	if minimal {
		return writeInitServerTomlMinimal(path, bind, port)
	}
	return writeInitServerTomlRecommended(path, bind, port, dataDir, profile)
}

func writeInitServerTomlMinimal(path, bind string, port int) error {
	content := fmt.Sprintf(`# Generated by sshkey-ctl init.
# Edit this file as needed; missing sections use built-in defaults.

[server]
port = %d
bind = %q
`, port, bind)
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeInitServerTomlRecommended(path, bind string, port int, dataDir, profile string) error {
	content, err := renderInitRecommendedServerToml(bind, port, dataDir, profile)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func renderInitRecommendedServerToml(bind string, port int, dataDir, profile string) (string, error) {
	if strings.TrimSpace(defaultServerTOMLRecommended) == "" {
		return "", fmt.Errorf("default server.toml template is empty")
	}
	lines := strings.Split(defaultServerTOMLRecommended, "\n")
	inServerSection := false
	inLoggingSection := false
	portReplaced := false
	bindReplaced := false
	logFileReplaced := false
	for i := range lines {
		line := strings.TrimSpace(lines[i])
		switch {
		case line == "[server]":
			inServerSection = true
			inLoggingSection = false
		case line == "[logging]":
			inLoggingSection = true
			inServerSection = false
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			inServerSection = false
			inLoggingSection = false
		}
		if inServerSection {
			if strings.HasPrefix(line, "port =") {
				lines[i] = fmt.Sprintf("port = %d", port)
				portReplaced = true
				continue
			}
			if strings.HasPrefix(line, "bind =") {
				lines[i] = fmt.Sprintf("bind = %q", bind)
				bindReplaced = true
				continue
			}
		}
		if inLoggingSection && strings.HasPrefix(line, "file =") {
			lines[i] = fmt.Sprintf("file = %q", filepath.Join(dataDir, "server.log"))
			logFileReplaced = true
			continue
		}
	}
	if !portReplaced || !bindReplaced {
		return "", fmt.Errorf("template missing [server] port/bind placeholders")
	}
	if !logFileReplaced {
		return "", fmt.Errorf("template missing [logging] file placeholder")
	}
	header := fmt.Sprintf(`# Generated by sshkey-ctl init (%s profile).
# This is the recommended full template with documented defaults.
# Edit values in place as needed.
`, profile)
	start := 0
	for start < len(lines) {
		trimmed := strings.TrimSpace(lines[start])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			start++
			continue
		}
		break
	}
	return header + "\n" + strings.Join(lines[start:], "\n"), nil
}
