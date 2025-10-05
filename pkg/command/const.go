package command

const (
	RootCmd         = "akashic"
	Version         = "0.0.2"
	FmtRootCmdShort = `akashic %s`
	FmtRootCmdLong  = "akashic %s\nOAuth 2.0 + OIDC SSO Server"

	RunCmd      = "run"
	RunCmdShort = "Start the Akashic server"
	RunCmdLong  = `Start the Akashic server with auth and control plane endpoints.

The run command initializes and starts both the authentication server (OAuth/OIDC)
and the control server (management API). By default, both servers start automatically
unless the --no-auto-start flag is provided.`
)
