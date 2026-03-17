package command

import (
	"fmt"
	"path"
	"strings"
)

// Op is the type of command operation.
type Op int

const (
	OpGet      Op = iota
	OpSet
	OpList
	OpInvite
	OpRegister
	OpHelp
	OpVaultCreate
	OpVaultInvite
	OpVaultAccept
	OpVaultPromote
	OpVaultMembers
	OpVaultList
	OpVaultDemote
	OpVaultDestroy
	OpVaultRevoke
	OpMove
)

// String returns the lowercase name of the operation.
func (op Op) String() string {
	switch op {
	case OpGet:
		return "get"
	case OpSet:
		return "set"
	case OpList:
		return "list"
	case OpInvite:
		return "invite"
	case OpRegister:
		return "register"
	case OpHelp:
		return "help"
	case OpVaultCreate:
		return "vault create"
	case OpVaultInvite:
		return "vault invite"
	case OpVaultAccept:
		return "vault accept"
	case OpVaultPromote:
		return "vault promote"
	case OpVaultDemote:
		return "vault demote"
	case OpVaultMembers:
		return "vault members"
	case OpVaultList:
		return "vault list"
	case OpVaultDestroy:
		return "vault destroy"
	case OpVaultRevoke:
		return "vault revoke"
	case OpMove:
		return "move"
	default:
		return "unknown"
	}
}

// Command represents a parsed user command.
type Command struct {
	Op         Op
	Path       string // for get/set/list/move (source path for move)
	Vault      string // vault name from colon syntax (empty = personal vault)
	InviteCode string // for register and vault accept
	TargetUser string // for vault invite/promote
	TargetPath string // for move: destination path
	TargetVault string // for move: destination vault
	GlobMatch  bool   // true when list/ls argument ended with *; Path is a literal prefix
}

// Parse parses an SSH command argv slice into a Command.
// Returns an error for unknown commands, missing required arguments, or unsafe paths.
func Parse(argv []string) (Command, error) {
	if len(argv) == 0 {
		return Command{}, fmt.Errorf("no command provided")
	}

	op := argv[0]
	args := argv[1:]

	switch op {
	case "get":
		if len(args) != 1 {
			return Command{}, fmt.Errorf("get requires exactly one path argument")
		}
		vault, p, err := parseVaultPath(args[0])
		if err != nil {
			return Command{}, err
		}
		return Command{Op: OpGet, Path: p, Vault: vault}, nil

	case "set":
		if len(args) != 1 {
			return Command{}, fmt.Errorf("set requires exactly one path argument")
		}
		vault, p, err := parseVaultPath(args[0])
		if err != nil {
			return Command{}, err
		}
		return Command{Op: OpSet, Path: p, Vault: vault}, nil

	case "list", "ls":
		if len(args) > 1 {
			return Command{}, fmt.Errorf("%s accepts at most one prefix argument", op)
		}
		if len(args) == 0 {
			return Command{Op: OpList}, nil
		}
		return parseListArg(args[0])

	case "invite":
		if len(args) != 0 {
			return Command{}, fmt.Errorf("invite takes no arguments")
		}
		return Command{Op: OpInvite}, nil

	case "register":
		if len(args) != 1 {
			return Command{}, fmt.Errorf("register requires exactly one invite code argument")
		}
		if err := validateInviteCode(args[0]); err != nil {
			return Command{}, err
		}
		return Command{Op: OpRegister, InviteCode: args[0]}, nil

	case "vault":
		return parseVaultSubcommand(args)

	case "move":
		return parseMoveCommand(args)

	case "help":
		return Command{Op: OpHelp}, nil

	default:
		return Command{}, fmt.Errorf("unknown command %q", op)
	}
}

// parseVaultPath splits "vault:path" into (vault, path), sanitizing the path.
// "personal:path" is treated the same as "path" (empty vault = personal).
func parseVaultPath(arg string) (string, string, error) {
	vault, rawPath, hasColon := strings.Cut(arg, ":")
	if !hasColon {
		// No colon: personal vault
		p, err := sanitizePath(arg)
		if err != nil {
			return "", "", err
		}
		return "", p, nil
	}

	if vault == "personal" {
		vault = ""
	}
	if vault != "" {
		if err := validateVaultRef(vault); err != nil {
			return "", "", err
		}
	}

	p, err := sanitizePath(rawPath)
	if err != nil {
		return "", "", err
	}
	return vault, p, nil
}

// parseListArg parses a list/ls argument that may contain vault prefix and/or glob.
func parseListArg(arg string) (Command, error) {
	vault := ""
	remainder := arg

	// Check for vault prefix (colon syntax)
	if idx := strings.Index(arg, ":"); idx >= 0 {
		vault = arg[:idx]
		remainder = arg[idx+1:]
		if vault == "personal" {
			vault = ""
		}
		if vault != "" {
			if err := validateVaultRef(vault); err != nil {
				return Command{}, err
			}
		}
	}

	// Empty remainder after colon: list all in vault
	if remainder == "" {
		return Command{Op: OpList, Vault: vault}, nil
	}

	// Check for glob
	if strings.HasSuffix(remainder, "*") {
		prefix, err := sanitizeGlobPrefix(strings.TrimSuffix(remainder, "*"))
		if err != nil {
			return Command{}, err
		}
		return Command{Op: OpList, Path: prefix, Vault: vault, GlobMatch: true}, nil
	}

	p, err := sanitizePath(remainder)
	if err != nil {
		return Command{}, err
	}
	return Command{Op: OpList, Path: p, Vault: vault}, nil
}

// parseVaultSubcommand parses "vault <subcommand> ..." args.
func parseVaultSubcommand(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("vault requires a subcommand: create, invite, accept, promote, demote, revoke, members, list, destroy")
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "create":
		if len(subArgs) != 1 {
			return Command{}, fmt.Errorf("vault create requires exactly one name argument")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		return Command{Op: OpVaultCreate, Vault: subArgs[0]}, nil

	case "invite":
		if len(subArgs) != 2 {
			return Command{}, fmt.Errorf("vault invite requires <name> <user>")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		if err := validateUsername(subArgs[1]); err != nil {
			return Command{}, fmt.Errorf("target user: %w", err)
		}
		return Command{Op: OpVaultInvite, Vault: subArgs[0], TargetUser: subArgs[1]}, nil

	case "accept":
		if len(subArgs) != 2 {
			return Command{}, fmt.Errorf("vault accept requires <name> <token>")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		return Command{Op: OpVaultAccept, Vault: subArgs[0], InviteCode: subArgs[1]}, nil

	case "promote":
		if len(subArgs) != 2 {
			return Command{}, fmt.Errorf("vault promote requires <name> <user>")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		if err := validateUsername(subArgs[1]); err != nil {
			return Command{}, fmt.Errorf("target user: %w", err)
		}
		return Command{Op: OpVaultPromote, Vault: subArgs[0], TargetUser: subArgs[1]}, nil

	case "demote":
		if len(subArgs) != 2 {
			return Command{}, fmt.Errorf("vault demote requires <name> <user>")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		if err := validateUsername(subArgs[1]); err != nil {
			return Command{}, fmt.Errorf("target user: %w", err)
		}
		return Command{Op: OpVaultDemote, Vault: subArgs[0], TargetUser: subArgs[1]}, nil

	case "members":
		if len(subArgs) != 1 {
			return Command{}, fmt.Errorf("vault members requires exactly one name argument")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		return Command{Op: OpVaultMembers, Vault: subArgs[0]}, nil

	case "list":
		if len(subArgs) != 0 {
			return Command{}, fmt.Errorf("vault list takes no arguments")
		}
		return Command{Op: OpVaultList}, nil

	case "destroy":
		if len(subArgs) != 1 {
			return Command{}, fmt.Errorf("vault destroy requires exactly one name argument")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		return Command{Op: OpVaultDestroy, Vault: subArgs[0]}, nil

	case "revoke":
		if len(subArgs) != 2 {
			return Command{}, fmt.Errorf("vault revoke requires <name> <user>")
		}
		if err := validateVaultName(subArgs[0]); err != nil {
			return Command{}, err
		}
		if err := validateUsername(subArgs[1]); err != nil {
			return Command{}, fmt.Errorf("target user: %w", err)
		}
		return Command{Op: OpVaultRevoke, Vault: subArgs[0], TargetUser: subArgs[1]}, nil

	default:
		return Command{}, fmt.Errorf("unknown vault subcommand %q", sub)
	}
}

// parseMoveCommand parses "move <src> <dst>" where src/dst may have vault prefixes.
func parseMoveCommand(args []string) (Command, error) {
	if len(args) != 2 {
		return Command{}, fmt.Errorf("move requires exactly two arguments: <src> <dst>")
	}

	srcVault, srcPath, err := parseVaultPath(args[0])
	if err != nil {
		return Command{}, fmt.Errorf("source: %w", err)
	}
	dstVault, dstPath, err := parseVaultPath(args[1])
	if err != nil {
		return Command{}, fmt.Errorf("destination: %w", err)
	}

	return Command{
		Op:          OpMove,
		Vault:       srcVault,
		Path:        srcPath,
		TargetVault: dstVault,
		TargetPath:  dstPath,
	}, nil
}

const maxVaultNameLength = 64
const maxUsernameLength = 64

// validateVaultRef validates a vault name used in colon-syntax references.
func validateVaultRef(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > maxVaultNameLength {
		return fmt.Errorf("vault name exceeds maximum length of %d characters", maxVaultNameLength)
	}
	for _, c := range name {
		if c == '/' || c == '.' || c == '\\' || c == ':' || c == '\x00' ||
			c == '*' || c == '?' || c == '[' || c == ']' {
			return fmt.Errorf("vault name contains invalid character %q", c)
		}
	}
	return nil
}

// validateVaultName validates a vault name used in vault management subcommands.
// Mirrors vault.ValidateVaultName to catch invalid names at parse time.
func validateVaultName(name string) error {
	if name == "" {
		return fmt.Errorf("vault name cannot be empty")
	}
	if len(name) > maxVaultNameLength {
		return fmt.Errorf("vault name exceeds maximum length of %d characters", maxVaultNameLength)
	}
	if name == "personal" {
		return fmt.Errorf("vault name %q is reserved", name)
	}
	if strings.HasPrefix(name, "_") {
		return fmt.Errorf("vault names starting with '_' are reserved")
	}
	for _, c := range name {
		if c == '/' || c == '.' || c == '\\' || c == ':' || c == '\x00' ||
			c == '*' || c == '?' || c == '[' || c == ']' {
			return fmt.Errorf("vault name contains invalid character %q", c)
		}
	}
	return nil
}

// sanitizeGlobPrefix validates a glob prefix (the part before a trailing *).
// Unlike sanitizePath it does not call path.Clean, preserving a trailing slash
// so that "account/*" matches only under "account/" and not "accountant/...".
func sanitizeGlobPrefix(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	if len(p) > maxPathLength {
		return "", fmt.Errorf("path exceeds maximum length of %d characters", maxPathLength)
	}
	if path.IsAbs(p) {
		return "", fmt.Errorf("path must be relative")
	}
	for _, component := range strings.Split(p, "/") {
		if component == ".." || component == "." {
			return "", fmt.Errorf("path component %q is not allowed", component)
		}
		if strings.HasPrefix(component, ".") {
			return "", fmt.Errorf("path component %q is not allowed (starts with '.')", component)
		}
	}
	return p, nil
}

const maxPathLength = 512

// sanitizePath cleans a secret path and rejects unsafe components.
// Rejects paths with components starting with '.' (blocks .., .ssh, etc.).
func sanitizePath(p string) (string, error) {
	if len(p) > maxPathLength {
		return "", fmt.Errorf("path exceeds maximum length of %d characters", maxPathLength)
	}
	if strings.Contains(p, ":") {
		return "", fmt.Errorf("path must not contain ':'")
	}
	cleaned := path.Clean(p)
	// path.Clean may produce an absolute path if p starts with /; reject that
	if path.IsAbs(cleaned) {
		return "", fmt.Errorf("path must be relative")
	}
	// Reject dot and double-dot as the entire path
	if cleaned == "." || cleaned == ".." {
		return "", fmt.Errorf("path %q is not allowed", p)
	}
	// Reject any component starting with '.'
	for _, component := range strings.Split(cleaned, "/") {
		if strings.HasPrefix(component, ".") {
			return "", fmt.Errorf("path component %q is not allowed (starts with '.')", component)
		}
	}
	return cleaned, nil
}

// validateInviteCode rejects invite codes containing path-unsafe or
// control characters. Control characters (< 0x20) are rejected to
// prevent log injection and filesystem edge cases.
func validateInviteCode(code string) error {
	for _, c := range code {
		if c == '/' || c == '\\' || c == '.' || c < ' ' {
			return fmt.Errorf("invite code contains invalid character")
		}
	}
	return nil
}
