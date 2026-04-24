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
)

type initOptions struct {
	configDir string
	dataDir   string
	bind      string
	port      int

	createStarterRooms bool
	starterRooms       []string
	markStarterDefault bool
}

func cmdInit(configDir, dataDir string, args []string) error {
	tty := term.IsTerminal(int(os.Stdin.Fd()))
	return cmdInitWithIO(configDir, dataDir, args, os.Stdin, os.Stdout, tty)
}

func cmdInitWithIO(configDir, dataDir string, args []string, in io.Reader, out io.Writer, tty bool) error {
	opts := initOptions{
		configDir:          configDir,
		dataDir:            dataDir,
		bind:               defaultBindAddr,
		port:               defaultPort,
		createStarterRooms: true,
		starterRooms:       []string{"general", "support"},
		markStarterDefault: true,
	}

	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dockerPreset bool
	var yes bool
	var noStarterRooms bool
	var noDefaultStarter bool
	var starterCSV string
	var bind string
	var port int
	var configOverride string
	var dataOverride string
	fs.BoolVar(&dockerPreset, "docker", false, "use docker defaults")
	fs.BoolVar(&yes, "yes", false, "non-interactive mode")
	fs.BoolVar(&noStarterRooms, "no-starter-rooms", false, "do not create starter rooms")
	fs.BoolVar(&noDefaultStarter, "no-default-starter-rooms", false, "do not mark starter rooms as default")
	fs.StringVar(&starterCSV, "starter-rooms", "", "comma-separated starter rooms")
	fs.StringVar(&bind, "bind", "", "bind address")
	fs.IntVar(&port, "port", 0, "port")
	fs.StringVar(&configOverride, "config", "", "config directory")
	fs.StringVar(&dataOverride, "data", "", "data directory")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("usage: init [--docker] [--yes] [--config DIR] [--data DIR] [--bind ADDR] [--port N]")
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("usage: init [--docker] [--yes] [--config DIR] [--data DIR] [--bind ADDR] [--port N]")
	}

	if dockerPreset {
		// Preserve explicit overrides if provided.
		if configDir == defaultConfigDir {
			opts.configDir = defaultConfigDir
		}
		if dataDir == defaultDataDir {
			opts.dataDir = defaultDataDir
		}
	}
	if configOverride != "" {
		opts.configDir = configOverride
	}
	if dataOverride != "" {
		opts.dataDir = dataOverride
	}
	if bind != "" {
		opts.bind = strings.TrimSpace(bind)
	}
	if port != 0 {
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
		if err := writeInitServerToml(serverPath, opts.bind, opts.port); err != nil {
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
	if opts.createStarterRooms {
		fmt.Fprintf(out, "  Starter rooms ensured: %d (created this run: %d)\n", len(opts.starterRooms), createdRooms)
		if opts.markStarterDefault {
			fmt.Fprintf(out, "  Starter rooms default-flagged: %d\n", defaultFlagged)
		}
	}
	return nil
}

func writeInitServerToml(path, bind string, port int) error {
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
