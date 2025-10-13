package cli

const (
	RootCmd         = "akashic-cli"
	Version         = "0.0.2"
	FmtRootCmdShort = "Akashic CLI %s - Administrative tool for Akashic server"
	FmtRootCmdLong  = `Akashic CLI %s is a command-line tool for managing the Akashic server.

It connects to the Akashic control plane API (default: http://localhost:8081)
and allows you to perform administrative tasks such as:

- Bootstrap root user creation
- User management (create, list, disable, enable)
- Server control (start, stop, restart, status)
- Configuration management (view, reload)
`
	FmtRootExamples = `# Check bootstrap status
akashic-cli bootstrap status

# Create root user (during bootstrap)
akashic-cli bootstrap create-root --token <token> --username root --email root@example.com

# Create an admin user
akashic-cli user create --username admin --email admin@example.com --type admin

# List all users
akashic-cli user list

# Check server status
akashic-cli server status

# Restart auth server
akashic-cli server restart`
)

const (
	PkiCmd      = "pki"
	PkiCmdShort = "Manage Akashic PKI certificates"
	PkiCmdLong  = `Manage Akashic PKI certificates using Hashicorp Vault.`
)
