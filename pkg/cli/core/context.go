package core

import (
	"akashic/akashic/pkg/common"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
	"golang.org/x/term"
)

type CliContext struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *viper.Viper
}

func NewCliContext() *CliContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &CliContext{
		ctx:    ctx,
		cancel: cancel,
		cfg:    viper.New(),
	}
}

func (ctx *CliContext) LogVerbose(format string, args ...any) {
	if ctx.cfg.GetBool("verbose") {
		log.Printf("[VERBOSE] "+format+"\n", args...)
	}
}

func (cmdCtx *CliContext) printResultTable(title string, data []string, footer string, isErr bool) {
	termWidth, _, err := term.GetSize(int(syscall.Stdout))
	hasTerm := err == nil
	if hasTerm {
		termWidth -= 8 // Give some space for better readability
	} else {
		cmdCtx.LogVerbose("Failed to get terminal size: %v", err)
	}
	r := renderer.NewColorized(
		renderer.ColorizedConfig{
			Settings: tw.Settings{
				Separators: tw.Separators{},
			},
			Header: renderer.Tint{
				FG: renderer.Colors{common.Ternary(isErr, color.FgRed, color.FgGreen), color.Bold},
				BG: renderer.Colors{},
			},
			Column: renderer.Tint{
				FG: renderer.Colors{common.Ternary(isErr, color.FgMagenta, color.Reset)},
				BG: renderer.Colors{},
			},
			Footer: renderer.Tint{
				FG: renderer.Colors{common.Ternary(isErr, color.Reset, color.FgCyan)},
				BG: renderer.Colors{},
			},
			Border: renderer.Tint{
				FG: renderer.Colors{color.FgWhite},
				BG: renderer.Colors{},
			},
			Separator: renderer.Tint{
				FG: renderer.Colors{color.FgWhite},
				BG: renderer.Colors{},
			},
			Symbols: tw.NewSymbols(tw.StyleRounded),
		},
	)
	rowCfg := tw.CellConfig{
		Formatting: tw.CellFormatting{
			AutoWrap: tw.WrapNone,
		},
		Padding: tw.CellPadding{
			Global: tw.Padding{
				Right: " ",
				Left:  " ",
			},
		},
	}
	footerCfg := tw.CellConfig{
		Formatting: tw.CellFormatting{
			AutoWrap: tw.WrapNone,
		},
		Padding: tw.CellPadding{
			Global: tw.Padding{
				Right: " ",
				Left:  " ",
			},
		},
	}
	if hasTerm {
		rowCfg.Formatting.AutoWrap = tw.WrapBreak
		rowCfg.ColMaxWidths = tw.CellWidth{Global: termWidth}
		footerCfg.Formatting.AutoWrap = tw.WrapBreak
		footerCfg.ColMaxWidths = tw.CellWidth{Global: termWidth}
	}
	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(r),
		tablewriter.WithRowConfig(rowCfg),
		tablewriter.WithFooterConfig(footerCfg),
		tablewriter.WithTrimSpace(tw.Off),
	)

	table.Header(title)
	// Split multi-line strings into separate rows so the tablewriter
	// correctly measures each line's width for column sizing.
	for _, d := range data {
		lines := strings.Split(d, "\n")
		for _, line := range lines {
			table.Append(line)
		}
	}
	table.Footer(footer)
	table.Render()
}

// resolveSecret resolves the AKASHIC_SECRET from env, file, or interactive prompt.
func (cmdCtx *CliContext) resolveSecret() (string, error) {
	secret := cmdCtx.cfg.GetString("secret")
	if secret == "" && cmdCtx.cfg.IsSet("secret_path") {
		cmdCtx.LogVerbose("Secret ENV not found, trying to read from secret_path")
		s, err := os.ReadFile(cmdCtx.cfg.GetString("secret_path"))
		if err == nil {
			secret = strings.TrimSpace(string(s))
		}
	}
	if secret == "" {
		cmdCtx.LogVerbose("Secret still not found, prompting for passphrase")
		fmt.Print("Enter passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase: %v", err)
		}
		secret = string(passphraseBytes)
	}
	return strings.TrimSpace(secret), nil
}

// resolveVaultToken reads and decrypts a Vault root token from an encrypted file.
func (cmdCtx *CliContext) resolveVaultToken() (string, error) {
	rootTokenFile := cmdCtx.cfg.GetString("vault.root_token_file")
	if rootTokenFile == "" {
		return "", fmt.Errorf("root token file is required (--root-token / -t)")
	}
	tokenFileBytes, err := os.ReadFile(rootTokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read root token file %s: %v", rootTokenFile, err)
	}
	tokenFileContents := strings.TrimSpace(string(tokenFileBytes))

	secret, err := cmdCtx.resolveSecret()
	if err != nil {
		return "", err
	}

	_, tokenData, err := ReadSecureToken(tokenFileContents, secret)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt root token: %v", err)
	}
	cmdCtx.LogVerbose("Root token decrypted successfully")
	return strings.TrimSpace(string(tokenData)), nil
}

// newAuthenticatedVaultClient creates an HTTP client configured for authenticated Vault API calls.
// Returns the client and the decrypted vault token.
func (cmdCtx *CliContext) newAuthenticatedVaultClient() (*HttpClient, string, error) {
	address := cmdCtx.cfg.GetString("vault.address")
	if address == "" {
		return nil, "", fmt.Errorf("vault address is not specified")
	}
	tlsConfig, err := getVaultTlsConfig(cmdCtx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create TLS configuration: %v", err)
	}
	client, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP client: %v", err)
	}
	vaultToken, err := cmdCtx.resolveVaultToken()
	if err != nil {
		return nil, "", err
	}
	return client, vaultToken, nil
}

const (
	SubjectRootToken  = "akashic/vault/root-token"
	SubjectUnsealKeys = "akashic/vault/unseal-key"
)

type FlagKey int

const (
	_ FlagKey = iota
	Verbose
	VaultAddress
	VaultCACert
	Secret
	SecretPath
	VaultNumKeys
	VaultNumThresholds
	VaultInitKeyOutDir
	VaultInitKeyOutFormat
	VaultInitRootOut
	VaultInitFileOverride
	TokenFileIn
	TokenFilesIn
	MinimumOutput
	TokenFileOut
	TokenFileOverride
	VaultUnsealOnce
	EngineDescription
	EngineConfigFile
	EngineConfig
	VaultRootTokenFile
	EngineName
	CsrOutput
	CsrCommonName
	SignCsrInput
	RegisterCertInput
	PkiCrlBaseUrl
)

var CliConfigMap = map[FlagKey]ConfigEntity[any]{
	// Verbose is only set via flag
	Verbose: {
		Key:        "verbose",
		Name:       "verbose",
		Short:      "v",
		Persistent: true,
		Default:    bool(false),
		Desc:       "Enable verbose output",
	},
	VaultAddress: {
		Key:        "vault.address",
		Env:        "AKASHIC_VAULT_ADDRESS",
		Name:       "address",
		Short:      "a",
		Persistent: true,
		Default:    string(""),
		Desc:       "Address to Hashicorp Vault",
	},
	VaultCACert: {
		Key:        "vault.cacert",
		Env:        "AKASHIC_VAULT_TLS_CACERT",
		Name:       "cacert",
		Short:      "c",
		Persistent: true,
		Default:    string(""),
		Desc:       "Path to CA certificate",
	},
	// VaultSecret is only set via env
	Secret: {
		Key: "secret",
		Env: "AKASHIC_SECRET",
	},
	SecretPath: {
		Key:     "secret_path",
		Env:     "AKASHIC_SECRET_PATH",
		Name:    "secret-path",
		Short:   "s",
		Default: string(""),
		Desc:    "Path to the secret in Vault",
	},
	VaultNumKeys: {
		Key:     "vault.keys",
		Env:     "AKASHIC_VAULT_NUM_KEYS",
		Name:    "keys",
		Default: int(5),
		Desc:    "Number of key shares to generate",
	},
	VaultNumThresholds: {
		Key:     "vault.thresholds",
		Env:     "AKASHIC_VAULT_NUM_THRESHOLDS",
		Name:    "thresholds",
		Default: int(3),
		Desc:    "Number of threshold keys to generate",
	},
	// VaultInitKeyOutDir is only set via flag
	VaultInitKeyOutDir: {
		Key:     "vault.key_out_dir",
		Name:    "key-out-dir",
		Default: string(""),
		Desc:    "Directory to output key files. If empty, it will be printed to stdout",
	},
	// VaultInitKeyOutFormat is only set via flag
	VaultInitKeyOutFormat: {
		Key:     "vault.key_out_format",
		Name:    "key-out-format",
		Default: string("key-%d.enc"),
		Desc:    "Format of key files name, it will insert number into '%d' in the format string. Only in effect when --key-out-dir is specified",
	},
	// VaultInitRootOut is only set via flag
	VaultInitRootOut: {
		Key:     "vault.root_out",
		Name:    "root-out",
		Default: string(""),
		Desc:    "Output file for root token. If empty, it will be printed to stdout",
	},
	VaultInitFileOverride: {
		Key:     "vault.init.file_override",
		Name:    "override",
		Short:   "f",
		Default: bool(false),
		Desc:    "Override existing Vault initialization files if they exist",
	},
	// TokenFileIn is only set via flag
	TokenFileIn: {
		Key:     "token.in",
		Name:    "in",
		Short:   "i",
		Default: string(""),
		Desc:    "Input file for token. If empty, it will be read from stdin",
	},
	// TokenFilesIn is only set via flag
	TokenFilesIn: {
		Key:     "token.ins",
		Name:    "in",
		Short:   "i",
		Default: []string{},
		Desc: `Input files for token. multiple files with globs are available (use , to separate the files).
Directory wide glob search are supported, for example, "./private/**/*.enc" will find all matching files under ./private/ directory.
Note that if you use glob expression, you must wrap the glob expression in double quotes,
Otherwise, shell will expand the glob expression before passing it to the command.
If globbing the file takes more than 5 seconds, the glob will be skipped.
This flag can be called multiple times. If empty, it will be reading token from stdin`,
	},
	// TokenFileOut is only set via flag
	TokenFileOut: {
		Key:     "token.out",
		Name:    "out",
		Short:   "o",
		Default: string(""),
		Desc:    "Output file for token. If empty, it will be written to stdout",
	},
	// TokenFileOverride is only set via flag
	TokenFileOverride: {
		Key:     "token.override",
		Name:    "override",
		Short:   "f",
		Default: bool(false),
		Desc:    "Override existing token file if it exists",
	},
	// MinimumOutput is only set via flag
	MinimumOutput: {
		Key:     "min_out",
		Name:    "min",
		Short:   "m",
		Default: bool(false),
		Desc:    "Only output the minimum required information, if failes, print nothing.",
	},
	// VaultUnsealOnce is only set via flag
	VaultUnsealOnce: {
		Key:     "vault.unseal_once",
		Name:    "once",
		Short:   "o",
		Default: bool(false),
		Desc: "Disable auto-unsealing feature that automatically try & finds working unsealing keys among the inputs, if they are available.\n" +
			"It will try to unseal the vault using each key once and exit.\n" +
			"- Tests each key sequentially without intelligent search\n" +
			"- Reports accept/reject status for each key individually\n" +
			"- Continues until vault unseals or all keys are tested\n" +
			"- No learning or optimization between attempts\n" +
			"- Best for: Debugging, testing known keys, or simple verification",
	},
	EngineDescription: {
		Key:     "engine.description",
		Name:    "description",
		Short:   "d",
		Default: string(""),
		Desc:    "Description for the mounted engine",
	},
	EngineConfigFile: {
		Key:     "engine.config_file",
		Name:    "config-file",
		Short:   "f",
		Default: string(""),
		Desc:    "Path to JSON file containing engine configuration (soft merges with defaults)",
	},
	EngineConfig: {
		Key:     "engine.config",
		Name:    "config",
		Default: string(""),
		Desc:    "Inline JSON string for engine configuration (soft merges over config file and defaults)",
	},
	VaultRootTokenFile: {
		Key:     "vault.root_token_file",
		Env:     "AKASHIC_VAULT_ROOT_TOKEN_FILE",
		Name:    "root-token",
		Short:   "t",
		Default: string(""),
		Desc:    "Path to encrypted root token file",
	},
	EngineName: {
		Key:     "engine.name",
		Name:    "engine",
		Short:   "e",
		Default: string(""),
		Desc:    "Target PKI engine mount path",
	},
	CsrOutput: {
		Key:     "csr.output",
		Name:    "output",
		Short:   "o",
		Default: string(""),
		Desc:    "Output file path for CSR",
	},
	CsrCommonName: {
		Key:     "csr.common_name",
		Name:    "cn",
		Default: string(""),
		Desc:    "Common name for the CSR (highest priority, overrides config)",
	},
	SignCsrInput: {
		Key:     "sign.csr_input",
		Name:    "csr",
		Default: string(""),
		Desc:    "Path to PEM-encoded CSR file to sign",
	},
	RegisterCertInput: {
		Key:     "register.cert_input",
		Name:    "cert",
		Default: string(""),
		Desc:    "Path to PEM-encoded signed certificate file to register",
	},
	PkiCrlBaseUrl: {
		Key:     "pki.crl_base_url",
		Env:     "AKASHIC_PKI_CRL_BASE_URL",
		Name:    "base-url",
		Default: string("http://localhost:8280"),
		Desc:    "Base URL for CRL/CA distribution endpoints",
	},
}

func FilterCliConfig(flagkeys ...FlagKey) []ConfigEntity[any] {
	filteredConfigs := make([]ConfigEntity[any], 0, len(flagkeys))
	for _, key := range flagkeys {
		entity, ok := CliConfigMap[key]
		if !ok {
			fmt.Printf("Missing config for flag key: %d\n", key)
			continue
		}
		filteredConfigs = append(filteredConfigs, entity)
	}
	return filteredConfigs
}

func (cmdCtx *CliContext) Init(cmd *cobra.Command, args []string) error {
	var err error

	// Set default configuration
	configs := slices.Collect(maps.Values(CliConfigMap))
	SetDefaults(cmdCtx.cfg, configs)

	// Load .env file if exists
	if err = godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("something went wrong while loading .env file: %v", err)
	}

	// Load environment variables to config
	if err = BindEnvs(cmdCtx.cfg, configs); err != nil {
		return err
	}

	// Bind flags to config
	if err = BindFlags(cmd, cmdCtx.cfg, configs); err != nil {
		return err
	}

	// Show colored output
	color.NoColor = false

	return nil
}

func getVaultTlsConfig(cmdCtx *CliContext) (*tls.Config, error) {
	cacert := cmdCtx.cfg.GetString("vault.cacert")
	var tlsConfig *tls.Config
	if cacert != "" {
		rootCrt, err := os.ReadFile(cacert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %v", err)
		}

		rootCaPool := x509.NewCertPool()

		if !rootCaPool.AppendCertsFromPEM(rootCrt) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig = &tls.Config{
			RootCAs: rootCaPool,
		}
	}
	return tlsConfig, nil
}

func (cmdCtx *CliContext) RunPkiVaultStatusCmd(cmd *cobra.Command, args []string) error {
	address := cmdCtx.cfg.GetString("vault.address")
	if address == "" {
		cmdCtx.printResultTable("VAULT STATUS FAILED", []string{
			"Vault address is not specified",
		}, "", true)
		os.Exit(1)
	}
	tlsConfig, err := getVaultTlsConfig(cmdCtx)
	if err != nil {
		cmdCtx.printResultTable("VAULT STATUS FAILED", []string{
			"Failed to create TLS configuration",
		}, err.Error(), true)
		os.Exit(1)
	}
	client, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		cmdCtx.printResultTable("VAULT STATUS FAILED", []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}

	resp, body, err := client.SendRequest(http.MethodGet, "/v1/sys/health", nil)
	if err != nil {
		cmdCtx.printResultTable("VAULT STATUS FAILED", []string{
			"Failed to get Vault status",
		}, err.Error(), true)
		os.Exit(1)
	}

	output, err := common.ConvJsonToYaml(body)
	if err != nil {
		cmdCtx.printResultTable("VAULT STATUS FAILED", []string{
			"failed to convert JSON to YAML",
		}, err.Error(), true)
		os.Exit(1)
	}

	output = strings.TrimSuffix(output, "\n")
	cmdCtx.printResultTable("VAULT STATUS RESULT", []string{
		output,
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultInitCmd(cmd *cobra.Command, args []string) error {
	address := cmdCtx.cfg.GetString("vault.address")
	if address == "" {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Vault address is not specified",
		}, "", true)
		os.Exit(1)
	}
	tlsConfig, err := getVaultTlsConfig(cmdCtx)
	if err != nil {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Failed to create TLS configuration",
		}, err.Error(), true)
		os.Exit(1)
	}
	getClient, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}
	resp, body, err := getClient.SendRequest(http.MethodGet, "/v1/sys/init", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Something went wrong while sending init request",
		}, err.Error(), true)
		os.Exit(1)
	}
	type initGetResponse struct {
		Initialized bool `json:"initialized"`
	}
	initResp := &initGetResponse{}
	err = json.Unmarshal(body, initResp)
	if err != nil {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Unable to parse init response",
		}, err.Error(), true)
		os.Exit(1)
	}
	if initResp.Initialized {
		cmdCtx.printResultTable("VAULT INIT SUCCESS", []string{
			"Vault is already initialized!",
		}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)
		os.Exit(0)
	}
	override := cmdCtx.cfg.GetBool("vault.init.file_override")
	numKey := cmdCtx.cfg.GetInt("vault.keys")
	if numKey < 1 {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Wrong number of keys specified",
		}, "number of keys must be greater than 0", true)
		os.Exit(1)
	}
	numThreshold := cmdCtx.cfg.GetInt("vault.thresholds")
	if numThreshold < 1 || numThreshold > numKey {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Wrong number of key threshold specified",
		}, "number of thresholds must be between 1 and number of keys", true)
		os.Exit(1)
	}
	keyOutDir := cmdCtx.cfg.GetString("vault.key_out_dir")
	var mkdirCallback func() error // use callback so we can defer the creation of the directory
	if keyOutDir != "" && !strings.ContainsRune(keyOutDir, 0) && !strings.ContainsAny(keyOutDir, `<>:"\|?*`) {
		cleanPath := filepath.Clean(keyOutDir)
		info, err := os.Stat(cleanPath)
		if os.IsNotExist(err) {
			mkdirCallback = func() error {
				if mkdirErr := os.MkdirAll(cleanPath, 0o755); mkdirErr != nil {
					return fmt.Errorf("failed to create key output directory: %v", mkdirErr)
				}
				cmdCtx.LogVerbose("Key output directory created: %s", cleanPath)
				return nil
			}
		} else if err != nil {
			cmdCtx.printResultTable("VAULT INIT FAILED", []string{
				"Failed to get key output directory info",
			}, err.Error(), true)
			os.Exit(1)
		} else if !info.IsDir() {
			cmdCtx.printResultTable("VAULT INIT FAILED", []string{
				"Something went wrong while preparing key output directory",
			}, "key output directory is not a directory: "+cleanPath, true)
			os.Exit(1)
		} else {
			cmdCtx.LogVerbose("Key output directory verified: %s", cleanPath)
		}
	} else {
		keyOutDir = ""
		cmdCtx.LogVerbose("Key output directory not set, result will not be saved and printed to stdout")
	}
	keyOutFormat := cmdCtx.cfg.GetString("vault.key_out_format")
	if !strings.Contains(keyOutFormat, "%d") {
		splited := strings.Split(keyOutFormat, ".")
		if len(splited) == 1 {
			keyOutFormat = fmt.Sprintf("%s-%%d", splited[0])
		} else {
			splited[len(splited)-2] = fmt.Sprintf("%s-%%d", splited[len(splited)-2])
			keyOutFormat = strings.Join(splited, ".")
		}
	}
	cmdCtx.LogVerbose("Key output format: %s", keyOutFormat)

	keyFiles := make([]string, 0, numKey)
	if keyOutDir != "" {
		for i := range numKey {
			fileName := strings.ReplaceAll(keyOutFormat, "%d", strconv.Itoa(i+1))
			fullPath := filepath.Join(keyOutDir, fileName)
			fullPath, err := filepath.Abs(fullPath)
			if err != nil {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					fmt.Sprintf("Failed to get absolute path of key output file \"%s\"", fullPath),
				}, err.Error(), true)
				os.Exit(1)
			}
			keyFiles = append(keyFiles, filepath.Clean(fullPath))
		}
	}
	cmdCtx.LogVerbose("Key output files: %v", keyFiles)

	// check if file exists
	for _, file := range keyFiles {
		info, err := os.Stat(file)
		if err != nil {
			if !os.IsNotExist(err) {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					"Failed to get key output file info",
				}, err.Error(), true)
				os.Exit(1)
			}
		} else if info.IsDir() {
			cmdCtx.printResultTable("VAULT INIT FAILED", []string{
				"Something went wrong while verifying key file",
			}, fmt.Sprintf("key output file is a directory: %s", file), true)
			os.Exit(1)
		} else {
			cmdCtx.LogVerbose("Key output file verified: %s", file)
			if !override {
				fmt.Printf("Key output file already exist \"%v\"\n", file)
				fmt.Print("Do you want to overwrite it? (y/N): ")
				var confirm string
				fmt.Scanln(&confirm)
				confirm = strings.TrimSpace(strings.ToLower(confirm))
				if confirm != "y" && confirm != "yes" {
					fmt.Println("Aborted")
					os.Exit(1)
				}
			}
		}
	}

	rootFile := cmdCtx.cfg.GetString("vault.root_out")
	var mkrootCallback func(data []byte) error // use callback so we can defer the creation of the file
	if rootFile != "" {
		rootFile = filepath.Clean(rootFile)
		rootDir := filepath.Dir(rootFile)
		mkrootCallback = func(data []byte) error {
			if mkrootdirerr := os.MkdirAll(rootDir, 0o755); mkrootdirerr != nil {
				return fmt.Errorf("failed to create root output directory: %v", mkrootdirerr)
			}
			cmdCtx.LogVerbose("Root output directory created: %s", rootDir)

			f, err := os.OpenFile(rootFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return fmt.Errorf("failed to create root output file: %v", err)
			}
			defer f.Close()

			_, err = f.Write(data)
			if err != nil {
				return fmt.Errorf("failed to write to root output file: %v", err)
			}

			return nil
		}
		info, err := os.Stat(rootFile)
		if err != nil {
			if !os.IsNotExist(err) {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					"Failed to get root output directory info",
				}, err.Error(), true)
				os.Exit(1)
			}
		} else if info.IsDir() {
			cmdCtx.printResultTable("VAULT INIT FAILED", []string{
				"Something went wrong while verifying root output file",
			}, fmt.Sprintf("root output file should not be a directory: %s", rootFile), true)
			os.Exit(1)
		} else {
			// confirm overwrite
			absPath, err := filepath.Abs(rootFile)
			if err != nil {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					fmt.Sprintf("Failed to get absolute path of root output file \"%s\"", rootFile),
				}, err.Error(), true)
				os.Exit(1)
			}
			if !override {
				fmt.Printf("Root output file already exist \"%v\"\n", absPath)
				fmt.Print("Do you want to overwrite the root output file? (y/N): ")
				var confirm string
				fmt.Scanln(&confirm)
				confirm = strings.TrimSpace(strings.ToLower(confirm))
				if confirm != "y" && confirm != "yes" {
					fmt.Println("Aborted")
					os.Exit(1)
				}
			}
		}
	} else {
		rootFile = ""
		cmdCtx.LogVerbose("Root output file not set, result will not be saved and printed to stdout")
	}

	secret := cmdCtx.cfg.GetString("secret")
	if rootFile != "" || keyOutDir != "" {
		if secret == "" && cmdCtx.cfg.IsSet("secret_path") {
			s, err := os.ReadFile(cmdCtx.cfg.GetString("secret_path"))
			if err == nil {
				secret = strings.TrimSpace(string(s))
			}
		}
		if secret == "" {
			fmt.Print("Enter passphrase to encrypt your data: ")
			passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					"Something went wrong while reading passphrase",
				}, err.Error(), true)
				os.Exit(1)
			}
			secret = string(passphraseBytes)

			fmt.Print("Confirm passphrase: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					"Something went wrong while reading passphrase confirmation",
				}, err.Error(), true)
				os.Exit(1)
			}
			if string(confirmBytes) != secret {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					"Passphrases do not match",
				}, "", true)
				os.Exit(1)
			}
		}
	}
	secret = strings.TrimSpace(secret)

	type JsonPayload struct {
		SecretShares    int `json:"secret_shares"`
		SecretThreshold int `json:"secret_threshold"`
	}
	jsonPayload := JsonPayload{
		SecretShares:    numKey,
		SecretThreshold: numThreshold,
	}
	postClient, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}

	resp, body, err = postClient.SendRequest(http.MethodPost, "/v1/sys/init", jsonPayload)
	if err != nil {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Failed to send initialization request",
		}, err.Error(), true)
		os.Exit(1)
	}

	type InitResponse struct {
		Keys       []string `json:"keys"`
		KeysBase64 []string `json:"keys_base64"`
		RootToken  string   `json:"root_token"`
	}
	initResponse := InitResponse{}
	err = json.Unmarshal(body, &initResponse)
	if err != nil {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Something went wrong while parsing initialization response",
			"You might need to reset the vault data volume and try again.",
		}, err.Error(), true)
		os.Exit(1)
	}
	if len(initResponse.Keys) != numKey {
		cmdCtx.printResultTable("VAULT INIT FAILED", []string{
			"Assertion failed",
		}, fmt.Sprintf("expected %d keys, got %d", numKey, len(initResponse.Keys)), true)
		os.Exit(1)
	}

	var reportBody []string
	reportBody = append(reportBody, fmt.Sprintf(
		"Requested Unseal keys      : %d\n"+
			"Requested Unseal threshold : %d",
		numKey, numThreshold,
	))
	keyStr := ""
	if keyOutDir == "" {
		keyStr += fmt.Sprintln("!! Key output directory is not set, your unseal key(s) will be exposed to the screen. Keep your keys safe !!")
		for i, key := range initResponse.Keys {
			keyStr += fmt.Sprintf("- Key %d: %s\n", i+1, key)
		}
	} else {
		keyEncData := make([]string, len(initResponse.Keys))
		for i, key := range initResponse.Keys {
			token, err := IssueSecureToken([]byte(key), secret, TokenMeta{
				Enc: AES_256_GCM,
				Alg: HMAC_SHA256,
				Sub: SubjectUnsealKeys,
				Dtl: fmt.Sprintf("Hashicorp vault unseal key (%d/%d) threshold: %d", i+1, numKey, numThreshold),
				Iss: "akashic-cli",
				Cnt: TEXT,
			})
			if err != nil {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					"Something went wrong while issuing secure token",
					"You might need to reset the vault data volume and try again.",
				}, err.Error(), true)
				os.Exit(1)
			}
			keyEncData[i] = token
		}

		if mkdirCallback != nil {
			if err := mkdirCallback(); err != nil {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					"Failed to create key output directory",
					"You might need to reset the vault data volume and try again.",
				}, err.Error(), true)
				os.Exit(1)
			}
		}

		mkTokenFile := func(filename, token string) error {
			file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return fmt.Errorf("failed to create token file: %v", err)
			}
			defer file.Close()

			_, err = file.WriteString(token)
			if err != nil {
				return fmt.Errorf("failed to write token to file: %v", err)
			}

			return nil
		}
		for i := range numKey {
			fileName := keyFiles[i]
			err := mkTokenFile(fileName, keyEncData[i])
			if err != nil {
				cmdCtx.printResultTable("VAULT INIT FAILED", []string{
					fmt.Sprintf("Failed to create secure token file \"%s\"", fileName),
					"You might need to reset the vault data volume and try again.",
				}, err.Error(), true)
				os.Exit(1)
			}
			keyStr += fmt.Sprintf("- Key %d saved to: %s (encrypted)\n", i+1, fileName)
		}
	}
	reportBody = append(reportBody, keyStr)

	rootStr := ""
	if rootFile == "" {
		rootStr += fmt.Sprintln("!! Root file is not set, your root token will be exposed to the screen. Keep your token safe !!")
		rootStr += fmt.Sprintf("- Root token: %s\n", initResponse.RootToken)
	} else {
		secureRootToken, err := IssueSecureToken([]byte(initResponse.RootToken), secret, TokenMeta{
			Enc: AES_256_GCM,
			Alg: HMAC_SHA256,
			Sub: SubjectRootToken,
			Dtl: "Hashicorp vault root token",
			Iss: "akashic-cli",
			Cnt: TEXT,
		})
		if err != nil {
			cmdCtx.printResultTable("VAULT INIT FAILED", []string{
				"Something went wrong while issuing secure token",
				"You might need to reset the vault data volume and try again.",
			}, err.Error(), true)
			os.Exit(1)
		}
		if mkrootCallback == nil {
			cmdCtx.printResultTable("VAULT INIT FAILED", []string{
				"Assertion failed",
				"You might need to reset the vault data volume and try again.",
			}, "root secure token file creation callback is missing", true)
			os.Exit(1)
		}
		if err := mkrootCallback([]byte(secureRootToken)); err != nil {
			cmdCtx.printResultTable("VAULT INIT FAILED", []string{
				"Something went wrong while creating root secure token file",
				"You might need to reset the vault data volume and try again.",
			}, err.Error(), true)
			os.Exit(1)
		}
		rootStr += fmt.Sprintf("- Root token saved to: %s (encrypted)\n", rootFile)
	}
	reportBody = append(reportBody, rootStr)

	cmdCtx.printResultTable("VAULT INIT RESULT", reportBody, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunTokenInspectCmd(cmd *cobra.Command, args []string) error {
	min := cmdCtx.cfg.GetBool("min_out")

	// Get secret passphrase to decrypt token
	secret, err := cmdCtx.resolveSecret()
	if err != nil {
		if min {
			os.Exit(1)
		}
		return err
	}

	// Get all file inputs
	inFiles := cmdCtx.cfg.GetStringSlice("token.ins")

	var tokenFiles []string
	delims := []rune{','}
	seen := make(map[string]struct{})
	add := func(path string) {
		abspath, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			cmdCtx.LogVerbose("Failed to resolve path: %v", err)
			return
		}
		if _, ok := seen[abspath]; !ok {
			seen[abspath] = struct{}{}
			tokenFiles = append(tokenFiles, abspath)
		} else {
			cmdCtx.LogVerbose("Dropping duplicate file input: %s", path)
		}
	}

	for _, fileBundle := range inFiles {
		delimiters := map[rune]bool{}
		for _, d := range delims {
			delimiters[d] = true
		}
		parts := strings.FieldsFunc(fileBundle, func(c rune) bool {
			return delimiters[c]
		})
		files := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				files = append(files, p)
			}
		}

		for _, f := range files {
			// glob expansion
			timeout := 5 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			matches, err := common.ExpandFileGlobsCtx(ctx, f, doublestar.WithFilesOnly())
			if err != nil {
				if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
					cmdCtx.LogVerbose("Glob expansion timeout: %v", err)
					if !min {
						fmt.Printf("Could not read all files matching '%s' due to timeout (%v)\n", f, timeout.String())
					}
				} else {
					cmdCtx.LogVerbose("Failed to glob file pattern: %v", err)
				}
				continue
			}
			if len(matches) == 0 {
				if info, err := os.Stat(f); err == nil && !info.IsDir() {
					add(f)
				} else {
					cmdCtx.LogVerbose("Token file is not found or is a directory: %s", f)
				}
				continue
			} else {
				for _, match := range matches {
					if info, err := os.Stat(match); err == nil && !info.IsDir() {
						add(match)
					} else {
						cmdCtx.LogVerbose("Token file is not found or is a directory: %s", match)
					}
					continue
				}
			}
		}
	}

	var token string
	if len(tokenFiles) == 0 && len(args) == 0 {
		fmt.Print("Enter token: ")
		fmt.Scanln(&token)
		token = strings.TrimSpace(token)
		if token == "" {
			if min {
				os.Exit(1)
			}
			return fmt.Errorf("no token provided")
		}
	}

	const (
		sourcePrompt = "PROMPT"
		sourceFile   = "FILE"
		sourceArgs   = "ARGS"
	)

	printResult := func(token string, secret string, source string) {
		success := false
		meta, data, readErr := ReadSecureToken(token, secret)
		if readErr != nil {
			cmdCtx.LogVerbose("Token ispection failed: %v", readErr)
		} else {
			success = true
		}

		if min {
			if !success {
				return
			}
			fmt.Println(string(data))
		} else {
			var tableTitle string
			var tableData []string
			var tableFooter string

			sourceRow := fmt.Sprintf("Source: %s", color.New(color.FgCyan).Sprint(source))
			if success {
				tableTitle = "Token Inspection Result"
				metaData := fmt.Sprintf(
					"Token Metadata:\n"+
						"- Token Subject        : %s\n"+
						"- Details              : %s\n"+
						"- Encryption Algorithm : %s\n"+
						"- Signature Algorithm  : %s\n"+
						"- Content Type         : %s\n"+
						"- Version              : %d\n"+
						"- Issuer               : %s\n"+
						"- Created At           : %s\n"+
						"- Key Salt             : %s\n",
					meta.Sub,
					meta.Dtl,
					meta.Alg,
					meta.Enc,
					meta.Cnt,
					meta.Ver,
					meta.Iss,
					time.Unix(meta.Iat, 0).Format(time.RFC3339),
					meta.Slt)
				tableData = []string{
					sourceRow,
					metaData,
				}
				var reformedData string
				switch meta.Cnt {
				case JSON:
					var j any
					if err := json.Unmarshal(data, &j); err != nil {
						reformedDataByte, err := json.MarshalIndent(j, "", "  ")
						if err != nil {
							reformedData = string(data)
						} else {
							reformedData = string(reformedDataByte)
						}
					}
				case YAML:
					var y any
					if err := yaml.Unmarshal(data, &y); err == nil {
						buf := &bytes.Buffer{}
						enc := yaml.NewEncoder(buf)
						enc.SetIndent(2)
						if err := enc.Encode(y); err != nil {
							reformedData = string(data)
						} else {
							reformedData = buf.String()
						}
					} else {
						reformedData = string(data)
					}
				case TEXT:
					reformedData = string(data)
				default:
					reformedData = string(data)
				}
				tableFooter = reformedData
			} else {
				tableTitle = "Token Inspection Failed"
				errorDetails := fmt.Sprintf(
					"Error Details:\n"+
						"- Is secure token error : %v\n",
					IsSecureTokenError(readErr),
				)
				tableData = []string{
					sourceRow,
					errorDetails,
				}
				tableFooter = readErr.Error()
			}

			var titleColor color.Attribute
			var footerColor color.Attribute
			if success {
				titleColor = color.FgGreen
				footerColor = color.FgYellow
			} else {
				titleColor = color.FgRed
				footerColor = color.FgMagenta
			}

			// Create table
			colorCfg := renderer.ColorizedConfig{
				Settings: tw.Settings{
					Separators: tw.Separators{
						BetweenRows: tw.On,
					},
				},
				Header: renderer.Tint{
					FG: renderer.Colors{titleColor, color.Bold},
					BG: renderer.Colors{},
				},
				Column: renderer.Tint{
					FG: renderer.Colors{color.Reset},
					BG: renderer.Colors{},
				},
				Footer: renderer.Tint{
					FG: renderer.Colors{footerColor},
					BG: renderer.Colors{},
				},
				Border: renderer.Tint{
					FG: renderer.Colors{color.FgWhite},
					BG: renderer.Colors{},
				},
				Separator: renderer.Tint{
					FG: renderer.Colors{color.FgWhite},
					BG: renderer.Colors{},
				},
				Symbols: tw.NewSymbols(tw.StyleRounded),
			}

			termWith, _, err := term.GetSize(int(syscall.Stdout))
			if err != nil {
				cmdCtx.LogVerbose("Failed to get terminal size: %v", err)
				termWith = 80
			} else {
				termWith -= 8 // Give some space for better readability
			}

			dataCfg := tw.CellConfig{
				Formatting: tw.CellFormatting{
					AutoWrap: tw.WrapBreak,
				},
				Padding: tw.CellPadding{
					Global: tw.Padding{
						Right: " ",
						Left:  " ",
					},
				},
				ColMaxWidths: tw.CellWidth{Global: termWith},
			}

			footerCfg := tw.CellConfig{
				Formatting: tw.CellFormatting{
					AutoWrap: tw.WrapBreak,
				},
				Padding: tw.CellPadding{
					Global: tw.Padding{
						Right: " ",
						Left:  " ",
					},
				},
				ColMaxWidths: tw.CellWidth{Global: termWith},
			}

			table := tablewriter.NewTable(os.Stdout,
				tablewriter.WithRenderer(renderer.NewColorized(colorCfg)),
				tablewriter.WithRowConfig(dataCfg),
				tablewriter.WithFooterConfig(footerCfg),
			)
			table.Header(tableTitle)
			table.Bulk(tableData)
			table.Footer(tableFooter)
			table.Render()
		}
	}

	if token != "" {
		printResult(token, secret, sourcePrompt)
	}

	for i, arg := range args {
		printResult(arg, secret, fmt.Sprintf("%s[%d]", sourceArgs, i))
	}

	for _, f := range tokenFiles {
		tokenBytes, err := os.ReadFile(f)
		if err != nil {
			cmdCtx.LogVerbose("Failed to read token from file: %v", err)
			continue
		}
		t := strings.TrimSpace(string(tokenBytes))
		printResult(t, secret, fmt.Sprintf("%s \"%s\"", sourceFile, f))
	}

	return nil
}
func (cmdCtx *CliContext) RunPkiVaultUnsealCmd(cmd *cobra.Command, args []string) error {
	var err error
	const (
		resultTitle       = "VAULT UNSEAL RESULT"
		failedTitle       = "VAULT UNSEAL FAILED"
		requestEndpoint   = "/v1/sys/unseal"
		statusEndpoint    = "/v1/sys/seal-status"
		GlobSearchTimeout = 5 * time.Second
	)
	type unsealResponse struct {
		Errors      []string `json:"errors"`
		Initialized bool     `json:"initialized"`
		Sealed      bool     `json:"sealed"`
		NumKeys     int      `json:"n"`
		Threshold   int      `json:"t"`
		Progress    int      `json:"progress"`
	}
	getUnsealStatus := func(client *HttpClient) (*http.Response, *unsealResponse, error) {
		resp, body, err := client.SendRequest(http.MethodGet, statusEndpoint, nil)
		if err != nil {
			return nil, nil, err
		}
		var rspBody unsealResponse
		if err = json.Unmarshal(body, &rspBody); err != nil {
			return nil, nil, err
		}
		return resp, &rspBody, nil
	}
	sendUnsealRequest := func(client *HttpClient, key string) (*http.Response, *unsealResponse, error) {
		type unsealReqJsonPayload struct {
			Key string `json:"key"`
		}
		payload := unsealReqJsonPayload{Key: key}
		resp, body, err := client.SendRequest(http.MethodPost, requestEndpoint, payload)
		if err != nil {
			return nil, nil, err
		}
		var rspBody unsealResponse
		if err = json.Unmarshal(body, &rspBody); err != nil {
			return nil, nil, err
		}
		return resp, &rspBody, nil
	}
	sendResetRequest := func(client *HttpClient) (*http.Response, *unsealResponse, error) {
		type resetReqJsonPayload struct {
			Reset bool `json:"reset"`
		}
		payload := resetReqJsonPayload{Reset: true}
		resp, body, err := client.SendRequest(http.MethodPost, requestEndpoint, payload)
		if err != nil {
			return nil, nil, err
		}
		var rspBody unsealResponse
		if err = json.Unmarshal(body, &rspBody); err != nil {
			return nil, nil, err
		}
		return resp, &rspBody, nil
	}
	runOnce := cmdCtx.cfg.GetBool("vault.unseal_once")
	if runOnce {
		cmdCtx.LogVerbose("Running vault unseal command without auto-recovery")
	}
	address := cmdCtx.cfg.GetString("vault.address")
	if address == "" {
		cmdCtx.printResultTable(failedTitle, []string{
			"Vault address is not specified",
		}, "", true)
		os.Exit(1)
	}
	tlsConfig, err := getVaultTlsConfig(cmdCtx)
	if err != nil {
		cmdCtx.printResultTable(failedTitle, []string{
			"Failed to create TLS configuration",
		}, err.Error(), true)
		os.Exit(1)
	}
	client, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		cmdCtx.printResultTable(failedTitle, []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}
	_, status, err := getUnsealStatus(client)
	if err != nil {
		cmdCtx.printResultTable(failedTitle, []string{
			"Failed to get vault seal status",
		}, err.Error(), true)
		os.Exit(1)
	}
	if !status.Initialized {
		cmdCtx.printResultTable(failedTitle, []string{
			"Vault is not initialized",
		}, "", true)
		os.Exit(1)
	}
	if !status.Sealed {
		cmdCtx.printResultTable(resultTitle, []string{
			"Vault is already unsealed",
		}, "", false)
		return nil
	}
	numKeys := status.NumKeys
	numThresholds := status.Threshold
	numProgress := status.Progress

	// Get all input files
	inFiles := cmdCtx.cfg.GetStringSlice("token.ins")

	var fileInputs []string
	seen := make(map[string]struct{}) // Avoid duplicate input files
	addFileInput := func(path string) {
		abspath, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			cmdCtx.LogVerbose("Failed to resolve absolute path: %v", err)
			return
		}
		if _, exists := seen[abspath]; exists {
			cmdCtx.LogVerbose("Dropping duplicate file input: %s", path)
		} else {
			seen[abspath] = struct{}{}
			fileInputs = append(fileInputs, abspath)
		}
	}

	for _, fileBundle := range inFiles {
		parts := strings.FieldsFunc(fileBundle, func(c rune) bool {
			return c == ','
		})
		files := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			files = append(files, p)
		}

		for _, f := range files {
			// glob expansion
			ctx, cancel := context.WithTimeout(context.Background(), GlobSearchTimeout)
			defer cancel()
			matches, err := common.ExpandFileGlobsCtx(ctx, f, doublestar.WithFilesOnly())
			if err != nil {
				var msg string
				if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
					msg = fmt.Sprintf("Glob expansion timed out: %v", GlobSearchTimeout.String())
				} else {
					msg = fmt.Sprintf("Failed to glob file pattern \"%v\": %v", f, err)
				}
				cmdCtx.printResultTable(failedTitle, []string{
					msg,
				}, err.Error(), true)
				os.Exit(1)
			}
			for _, file := range matches {
				if info, err := os.Stat(file); err == nil {
					if info.IsDir() {
						continue
					}
					addFileInput(file)
				} else {
					cmdCtx.printResultTable(failedTitle, []string{
						fmt.Sprintf("Failed to access file: %v", file),
					}, err.Error(), true)
					os.Exit(1)
				}
			}
		}
	}

	var secret string
	if len(fileInputs) > 0 {
		secret = cmdCtx.cfg.GetString("secret")
		if secret == "" && cmdCtx.cfg.IsSet("secret_path") {
			path := cmdCtx.cfg.GetString("secret_path")
			cmdCtx.LogVerbose("Secret ENV is not found, trying to read from secret path instead: %s", path)
			s, err := os.ReadFile(path)
			if err != nil {
				cmdCtx.printResultTable(failedTitle, []string{
					fmt.Sprintf("Failed to read secret from file: %v", path),
				}, err.Error(), true)
				os.Exit(1)
			}
			secret = strings.TrimSpace(string(s))
		}
		if secret == "" {
			cmdCtx.LogVerbose("Secret still not found, prompting for passphrase")
			fmt.Print("Enter passphrase: ")
			passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				cmdCtx.printResultTable(failedTitle, []string{
					"Failed to read passphrase",
				}, err.Error(), true)
				os.Exit(1)
			}
			secret = strings.TrimSpace(string(passphraseBytes))
		}
	}

	// unsealKeyCandidate represents a candidate unseal key with its source information
	type unsealKeyCandidate struct {
		Key    string
		Source string
	}

	// Collect all candidate keys from args and files
	unsealKeys := []*unsealKeyCandidate{}
	for i, arg := range args {
		unsealKeys = append(unsealKeys, &unsealKeyCandidate{
			Key:    arg,
			Source: fmt.Sprintf("COMMAND ARGUMENT %d", i+1),
		})
	}

	for _, file := range fileInputs {
		tokenBytes, err := os.ReadFile(file)
		if err != nil {
			cmdCtx.LogVerbose("Failed to read unseal key token from file \"%s\" (skiped): %v", file, err)
			continue
		}
		token := strings.TrimSpace(string(tokenBytes))

		meta, data, err := ReadSecureToken(token, secret)
		if err != nil {
			cmdCtx.LogVerbose("Token inspection failed for \"%s\" (skiped): %v", file, err)
			continue
		}
		if meta.Sub != SubjectUnsealKeys {
			cmdCtx.LogVerbose("Token is not a unseal key token (skiped): %s", file)
			continue
		}
		unsealKeys = append(unsealKeys, &unsealKeyCandidate{
			Key:    string(data),
			Source: fmt.Sprintf("TOKEN FILE: \"%s\"", file),
		})
	}

	if len(unsealKeys) == 0 {
		cmdCtx.printResultTable(failedTitle, []string{
			"No valid unseal key found",
		}, "", true)
		os.Exit(1)
	}

	type finalResult int
	const (
		_ = iota
		resultUnknown
		resultUnsealed // fully unsealed
		resultFailed   // unseal failed
		resultPartial  // partially unsealed (for run-once mode)
	)
	var result finalResult = resultUnknown

	// special handling for run-once mode
	if runOnce {
		cmdCtx.LogVerbose("Start unsealing with PB-SAT key discovery disabled...")
		resultData := color.New(color.FgYellow).Sprint("Key candidates") + ":\n"
		detail := ""
		isUnsealed := false
		for i, key := range unsealKeys {
			if isUnsealed {
				cmdCtx.LogVerbose("Vault is already unsealed, skipping remaining keys: %v", key.Source)
				resultData += fmt.Sprintf("[%s] #%d: %s\n",
					"UNUSED",
					i+1,
					color.New(color.FgCyan).Sprint(key.Source),
				)
				continue
			}
			_, body, err := sendUnsealRequest(client, key.Key)

			// something went wrong while sending the request
			if err != nil {
				cmdCtx.LogVerbose("Failed to send unseal request: %v", key.Source)
				resultData += fmt.Sprintf("[%s] #%d: %s\n",
					color.New(color.FgRed).Sprint("FAILED"),
					i+1,
					color.New(color.FgCyan).Sprint(key.Source),
				)
				detail += fmt.Sprintf("#%d: %s\n",
					i+1,
					color.New(color.FgMagenta).Sprint(err.Error()),
				)
				continue
			}

			// something went wrong while processing the request
			if body.Errors != nil {
				cmdCtx.LogVerbose("Vault rejected unseal key: %v", key.Source)
				errMsgs := []string{}
				for _, errstr := range body.Errors {
					parts := strings.Split(errstr, "\n")
					errMsgs = append(errMsgs, parts...)
				}
				resultData += fmt.Sprintf("[%s] #%d: %s\n",
					color.New(color.FgRed).Sprint("REJECT"),
					i+1,
					color.New(color.FgCyan).Sprint(key.Source),
				)
				if len(errMsgs) == 1 {
					detail += fmt.Sprintf("#%d: %s\n",
						i+1,
						color.New(color.FgMagenta).Sprint(errMsgs[0]),
					)
				} else if len(errMsgs) > 1 {
					detail += fmt.Sprintf("#%d:\n", i+1)
					for _, msg := range errMsgs {
						detail += fmt.Sprintf("- %s\n", color.New(color.FgMagenta).Sprint(msg))
					}
				}
				continue
			}

			progress := body.Progress
			if !body.Sealed {
				progress = body.Threshold
				isUnsealed = true
			}
			cmdCtx.LogVerbose("Key accepted, progress: %d/%d (%s)", progress, body.Threshold, key.Source)
			if body.Sealed {
				resultData += fmt.Sprintf("[%s] #%d: %s - progress %d/%d\n",
					color.New(color.FgGreen).Sprint("ACCEPT"),
					i+1,
					color.New(color.FgCyan).Sprint(key.Source),
					progress,
					body.Threshold,
				)
			} else {
				resultData += fmt.Sprintf("[%s] #%d: %s - progress %d/%d\n",
					color.New(color.FgGreen, color.Bold).Sprint("UNSEAL"),
					i+1,
					color.New(color.FgCyan).Sprint(key.Source),
					progress,
					body.Threshold,
				)
			}
		}

		_, status, err := getUnsealStatus(client)
		if err != nil {
			cmdCtx.LogVerbose("Failed to get unseal status: %v", err)
			result = resultUnknown
		}
		var resultTblTitle, progressFooter string
		switch result {
		case resultUnknown:
			resultTblTitle = "VAULT UNSEAL RESULT"
		case resultUnsealed:
			resultTblTitle = "VAULT UNSEALED"
		case resultFailed:
			resultTblTitle = "VAULT UNSEAL FAILED"
		case resultPartial:
			resultTblTitle = "VAULT PARTIALLY UNSEALED"
		}

		progress := status.Progress
		if !status.Sealed {
			result = resultUnsealed
			progress = status.Threshold
		} else {
			if status.Progress > numProgress {
				result = resultPartial
			} else {
				result = resultFailed
			}
		}
		if status.Sealed {
			progressFooter = color.New(color.FgYellow).Sprintf("Last unseal progress: %d/%d\n", progress, status.Threshold)
		} else {
			progressFooter = color.New(color.FgGreen, color.Bold).Sprint("Vault is now unsealed")
		}

		var data []string
		data = append(data, resultData)
		if detail != "" {
			detail = fmt.Sprintf("%s:\n%s", color.New(color.FgYellow).Sprint("Details"), detail)
			data = append(data, detail)
		}
		isErr := result == resultFailed || result == resultUnknown
		cmdCtx.printResultTable(resultTblTitle, data, progressFooter, isErr)
		return nil
	}

	cmdCtx.LogVerbose("Start unsealing with PB-SAT key discovery...")

	// Track test attempts for reporting
	type testAttempt struct {
		KeyIndices []int    // Indices into unsealKeys
		Success    bool     // Whether Vault was unsealed
		ErrMsgs    []string // Error message if failed
	}
	attempts := []testAttempt{}

	cmdCtx.LogVerbose("Total number of keys issued: %d", numKeys)
	cmdCtx.LogVerbose("Number of keys needed to unseal: %d", numThresholds)
	if numProgress != 0 {
		cmdCtx.LogVerbose("Resetting the progress...")
		_, rspBody, err := sendResetRequest(client)
		if err != nil {
			cmdCtx.printResultTable(failedTitle, []string{
				"Failed to reset Vault",
			}, err.Error(), true)
			os.Exit(1)
		}
		if rspBody.Errors != nil {
			errMsgs := []string{}
			for _, errstr := range rspBody.Errors {
				parts := strings.Split(errstr, "\n")
				errMsgs = append(errMsgs, parts...)
			}
			footer := "Error:\n"
			for _, msg := range errMsgs {
				footer += fmt.Sprintf("- %s\n", color.New(color.FgMagenta).Sprint(msg))
			}
			cmdCtx.printResultTable(failedTitle, []string{
				"Failed to reset Vault",
			}, footer, true)
			os.Exit(1)
		}
		if !rspBody.Sealed {
			cmdCtx.printResultTable(resultTitle, []string{
				"Vault is already unsealed",
			}, "", false)
			return nil
		}
		numKeys = rspBody.NumKeys
		numThresholds = rspBody.Threshold
	}

	satSolver := NewVaultKeySatSolver(len(unsealKeys), numThresholds, numKeys)

	for {
		keyIndices, err := satSolver.GetNextKeyCombination()
		if err != nil {
			cmdCtx.LogVerbose("SAT solver reports UNSAT: %v", err)
			result = resultFailed
			attempts = append(attempts, testAttempt{
				KeyIndices: keyIndices,
				Success:    false,
				ErrMsgs:    []string{err.Error()},
			})
			break
		}

		var testErr error
		var testRsp *unsealResponse
		cmdCtx.LogVerbose("Testing key combinations (0-indexed): %v", keyIndices)
		for i, keyIdx := range keyIndices {
			if i > 0 {
				time.Sleep(10 * time.Millisecond)
			}
			key := unsealKeys[keyIdx].Key
			cmdCtx.LogVerbose("Feeding key %d/%d: idx=%d", i+1, len(keyIndices), keyIdx)

			_, testRsp, testErr = sendUnsealRequest(client, key)
			if testErr != nil {
				cmdCtx.LogVerbose("Request failed: %v", testErr)
				satSolver.RecordFalseKey(keyIdx) // Mark this key as false key
				break
			}
			if testRsp.Errors != nil {
				cmdCtx.LogVerbose("Request rejected: %v", testErr)
				for _, errMsg := range testRsp.Errors {
					if strings.Contains(errMsg, "'key' must be a valid hex or base64 string") {
						cmdCtx.LogVerbose("Request was rejected due to invalid key format, adding to false key list")
						satSolver.RecordFalseKey(keyIdx) // Mark this key as false key
					}
				}
				break
			}
			cmdCtx.LogVerbose("Request accepted, progress: %d", testRsp.Progress)

			if !testRsp.Sealed {
				cmdCtx.LogVerbose("Vault unsealed")
				result = resultUnsealed
				break
			}
		}

		attemptRecord := testAttempt{
			KeyIndices: keyIndices,
			Success:    result == resultUnsealed,
			ErrMsgs:    []string{},
		}
		if testErr != nil {
			attemptRecord.ErrMsgs = append(attemptRecord.ErrMsgs, testErr.Error())
		}
		if testRsp.Errors != nil {
			attemptRecord.ErrMsgs = append(attemptRecord.ErrMsgs, testRsp.Errors...)
		}

		attempts = append(attempts, attemptRecord)
		if result == resultUnsealed {
			break
		}

		cmdCtx.LogVerbose("Test failed, adding constraint to SAT solver")
		satSolver.RecordFailure(keyIndices) // At least one of the tested key is false key

		// reset after failure
		cmdCtx.LogVerbose("Resetting the progress...")
		_, rspBody, err := sendResetRequest(client)
		if err != nil {
			cmdCtx.printResultTable(failedTitle, []string{
				"Failed to reset Vault",
			}, err.Error(), true)
			os.Exit(1)
		}
		if rspBody.Errors != nil {
			errMsgs := []string{}
			for _, errstr := range rspBody.Errors {
				parts := strings.Split(errstr, "\n")
				errMsgs = append(errMsgs, parts...)
			}
			footer := "Error:\n"
			for _, msg := range errMsgs {
				footer += fmt.Sprintf("- %s\n", color.New(color.FgMagenta).Sprint(msg))
			}
			cmdCtx.printResultTable(failedTitle, []string{
				"Failed to reset Vault",
			}, footer, true)
			os.Exit(1)
		}
		if !rspBody.Sealed {
			cmdCtx.printResultTable(resultTitle, []string{
				"Vault is already unsealed",
			}, "", false)
			return nil
		}
	}

	// Perform backbone analysis to classify keys
	cmdCtx.LogVerbose("Performing backbone analysis to classify remaining keys...")
	var successfulKeys []int
	if result == resultUnsealed {
		// Find the successful attempt to get the key indices
		for i := len(attempts) - 1; i >= 0; i-- {
			if attempts[i].Success {
				successfulKeys = attempts[i].KeyIndices
				break
			}
		}
	}

	backboneResult, err := satSolver.ComputeBackbone(result == resultUnsealed, successfulKeys)
	if err != nil {
		cmdCtx.LogVerbose("Backbone analysis failed: %v", err)
	}

	resultTblTitle := "VAULT UNSEAL RESULT"
	resultTblBody := []string{}
	resultTblFooter := ""

	// generate stats
	statsBody := color.New(color.FgYellow).Sprint("Statistics") + ":"
	attemptCounts, _ := satSolver.GetStats()
	statsBody += fmt.Sprintf("\n"+
		"- Total key candidates: %d\n"+
		"- Vault threshold: %d\n"+
		"- Total attempts: %d\n",
		len(unsealKeys),
		numThresholds,
		attemptCounts,
	)
	resultTblBody = append(resultTblBody, statsBody)

	// generate key candidates with backbone classification
	keyCandidatesBody := color.New(color.FgYellow).Sprint("Key Candidates") + ":\n"

	// Build classification maps for easy lookup
	keyClassification := make(map[int]string)
	if backboneResult != nil {
		for _, idx := range backboneResult.DefinitelyReal {
			keyClassification[idx] = "ACCEPT"
		}
		for _, idx := range backboneResult.DefinitelyFake {
			keyClassification[idx] = "REJECT"
		}
		for _, idx := range backboneResult.Undetermined {
			keyClassification[idx] = "UNSURE"
		}
	}

	for i, key := range unsealKeys {
		classification := keyClassification[i]
		if classification == "" {
			classification = "UNUSED"
		}

		var classColor *color.Color
		switch classification {
		case "ACCEPT":
			classColor = color.New(color.FgGreen, color.Bold)
		case "REJECT":
			classColor = color.New(color.FgRed)
		case "UNSURE":
			classColor = color.New(color.FgYellow)
		default:
			classColor = color.New(color.Reset)
		}

		keyCandidatesBody += fmt.Sprintf("- [%s] #%d: %s\n",
			classColor.Sprint(classification),
			i+1,
			color.New(color.FgCyan).Sprint(key.Source))
	}
	resultTblBody = append(resultTblBody, keyCandidatesBody)

	// generate attempts table
	attemptsBody := color.New(color.FgYellow).Sprint("Attempts") + ":\n"
	for i, a := range attempts {
		if a.KeyIndices != nil {
			status := ""
			if a.Success {
				status = color.New(color.FgGreen).Sprint("PASSED")
			} else {
				status = color.New(color.FgRed).Sprint("FAILED")
			}
			usedKeys := ""
			for _, k := range a.KeyIndices {
				if usedKeys != "" {
					usedKeys += ", "
				}
				usedKeys += color.New(color.FgCyan).Sprintf("#%d", k+1)
			}
			attemptsBody += fmt.Sprintf("%3d. [%s] Keys: %s\n", i+1, status, usedKeys)
			if a.ErrMsgs != nil {
				errMsgs := []string{}
				for _, errstr := range a.ErrMsgs {
					parts := strings.Split(errstr, "\n")
					errMsgs = append(errMsgs, parts...)
				}
				for _, msg := range errMsgs {
					attemptsBody += fmt.Sprintf("- %s\n", msg)
				}
			}
		} else {
			attemptsBody += fmt.Sprintf(
				"%3d. [%s]: %s\n",
				i+1,
				color.New(color.FgRed, color.Bold).Sprint("FAILED"),
				color.New(color.FgMagenta).Sprint("Unsatisfiable, no valid key combination exists"),
			)
		}
	}
	resultTblBody = append(resultTblBody, attemptsBody)

	// generate footer
	switch result {
	case resultUnknown:
		resultTblFooter = color.New(color.FgRed).Sprint("Something went wrong, result unknown")
	case resultUnsealed:
		resultTblFooter = color.New(color.FgGreen, color.Bold).Sprint("Vault is now unsealed")
	case resultFailed:
		resultTblFooter = color.New(color.FgRed, color.Bold).Sprint("Failed to unseal vault - no valid key combination found")
	}

	cmdCtx.printResultTable(resultTblTitle, resultTblBody, resultTblFooter, result == resultFailed || result == resultUnknown)
	return nil
}

func (cmdCtx *CliContext) RunPkiVaultEngineMountCmd(cmd *cobra.Command, args []string) error {
	// Parse mount path
	mountPath := strings.Trim(args[0], "/")
	if mountPath == "" {
		cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
			"Mount path is required",
		}, "", true)
		os.Exit(1)
	}
	cmdCtx.LogVerbose("Mount path: %s", mountPath)

	// Create authenticated Vault client
	client, vaultToken, err := cmdCtx.newAuthenticatedVaultClient()
	if err != nil {
		cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
			err.Error(),
		}, "", true)
		os.Exit(1)
	}

	// Check if engine is already mounted
	resp, body, err := client.SendRequestWithToken(http.MethodGet, "/v1/sys/mounts", nil, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
			"Failed to check existing mounts",
		}, err.Error(), true)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
			"Failed to list existing mounts",
		}, fmt.Sprintf("Status code: %d\n%s", resp.StatusCode, string(body)), true)
		os.Exit(1)
	}

	var mountsResponse map[string]json.RawMessage
	if err := json.Unmarshal(body, &mountsResponse); err != nil {
		cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
			"Failed to parse mounts response",
		}, err.Error(), true)
		os.Exit(1)
	}

	// Vault may wrap mounts in a "data" key or return them at top level
	mountsData := mountsResponse
	if dataRaw, ok := mountsResponse["data"]; ok {
		var dataMounts map[string]json.RawMessage
		if json.Unmarshal(dataRaw, &dataMounts) == nil {
			mountsData = dataMounts
		}
	}

	lookupKey := mountPath + "/"
	if _, exists := mountsData[lookupKey]; exists {
		cmdCtx.printResultTable("ENGINE MOUNT SUCCESS", []string{
			fmt.Sprintf("PKI engine already mounted at: %s", mountPath),
		}, "Already mounted", false)
		return nil
	}

	// Build cascading config: defaults → config file → inline config
	config := map[string]interface{}{
		"max_lease_ttl": "8760h",
	}

	configFilePath := cmdCtx.cfg.GetString("engine.config_file")
	if configFilePath != "" {
		fileBytes, err := os.ReadFile(configFilePath)
		if err != nil {
			cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
				fmt.Sprintf("Failed to read config file: %s", configFilePath),
			}, err.Error(), true)
			os.Exit(1)
		}
		var fileConfig map[string]interface{}
		if err := json.Unmarshal(fileBytes, &fileConfig); err != nil {
			cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
				"Failed to parse config file (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range fileConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from file: %s", configFilePath)
	}

	inlineConfig := cmdCtx.cfg.GetString("engine.config")
	if inlineConfig != "" {
		var parsedConfig map[string]interface{}
		if err := json.Unmarshal([]byte(inlineConfig), &parsedConfig); err != nil {
			cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
				"Failed to parse inline config (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range parsedConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from inline flag")
	}

	// Build mount request
	description := cmdCtx.cfg.GetString("engine.description")
	type MountRequest struct {
		Type        string                 `json:"type"`
		Description string                 `json:"description,omitempty"`
		Config      map[string]interface{} `json:"config"`
	}
	payload := MountRequest{
		Type:        "pki",
		Description: description,
		Config:      config,
	}

	cmdCtx.LogVerbose("Mounting PKI engine at: %s", mountPath)
	resp, body, err = client.SendRequestWithToken(http.MethodPost, "/v1/sys/mounts/"+mountPath, payload, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
			"Failed to send mount request",
		}, err.Error(), true)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		cmdCtx.printResultTable("ENGINE MOUNT FAILED", []string{
			fmt.Sprintf("Vault returned status %d", resp.StatusCode),
			string(body),
		}, "", true)
		os.Exit(1)
	}

	descInfo := ""
	if description != "" {
		descInfo = fmt.Sprintf("\nDescription: %s", description)
	}
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	cmdCtx.printResultTable("ENGINE MOUNT SUCCESS", []string{
		fmt.Sprintf("PKI engine mounted at: %s%s\nConfig: %s", mountPath, descInfo, string(configJSON)),
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultEngineGenerateCsrInternalCmd(cmd *cobra.Command, args []string) error {
	// Validate required flags
	engineName := cmdCtx.cfg.GetString("engine.name")
	if engineName == "" {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			"Engine name is required (--engine / -e)",
		}, "", true)
		os.Exit(1)
	}

	outputPath := cmdCtx.cfg.GetString("csr.output")
	if outputPath == "" {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			"Output file is required (--output / -o)",
		}, "", true)
		os.Exit(1)
	}

	cmdCtx.LogVerbose("Engine: %s, Output: %s", engineName, outputPath)

	// Create authenticated Vault client
	client, vaultToken, err := cmdCtx.newAuthenticatedVaultClient()
	if err != nil {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			err.Error(),
		}, "", true)
		os.Exit(1)
	}

	// Build cascading config: defaults → config file → inline config → --cn flag
	config := map[string]interface{}{
		"key_type":     "rsa",
		"key_bits":     4096,
		"format":       "pem",
		"organization": "Akashic",
		"ou":           "Security",
		"country":      "US",
	}

	configFilePath := cmdCtx.cfg.GetString("engine.config_file")
	if configFilePath != "" {
		fileBytes, err := os.ReadFile(configFilePath)
		if err != nil {
			cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
				fmt.Sprintf("Failed to read config file: %s", configFilePath),
			}, err.Error(), true)
			os.Exit(1)
		}
		var fileConfig map[string]interface{}
		if err := json.Unmarshal(fileBytes, &fileConfig); err != nil {
			cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
				"Failed to parse config file (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range fileConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from file: %s", configFilePath)
	}

	inlineConfig := cmdCtx.cfg.GetString("engine.config")
	if inlineConfig != "" {
		var parsedConfig map[string]interface{}
		if err := json.Unmarshal([]byte(inlineConfig), &parsedConfig); err != nil {
			cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
				"Failed to parse inline config (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range parsedConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from inline flag")
	}

	// --cn flag has highest priority
	cnFlag := cmdCtx.cfg.GetString("csr.common_name")
	if cnFlag != "" {
		config["common_name"] = cnFlag
	}

	// Validate common_name is present
	if _, ok := config["common_name"]; !ok {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			"common_name is required (use --cn or include in config file/inline)",
		}, "", true)
		os.Exit(1)
	}
	if cn, ok := config["common_name"].(string); ok && cn == "" {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			"common_name cannot be empty",
		}, "", true)
		os.Exit(1)
	}

	// Send CSR generation request
	apiPath := fmt.Sprintf("/v1/%s/intermediate/generate/internal", engineName)
	cmdCtx.LogVerbose("Generating CSR: POST %s", apiPath)

	resp, body, err := client.SendRequestWithToken(http.MethodPost, apiPath, config, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			"Failed to send CSR generation request",
		}, err.Error(), true)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			fmt.Sprintf("Vault returned status %d", resp.StatusCode),
			string(body),
		}, "", true)
		os.Exit(1)
	}

	// Parse response
	var csrResponse struct {
		Data struct {
			CSR   string `json:"csr"`
			KeyID string `json:"key_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &csrResponse); err != nil {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			"Failed to parse CSR response",
		}, err.Error(), true)
		os.Exit(1)
	}

	if csrResponse.Data.CSR == "" {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			"CSR not found in Vault response",
		}, string(body), true)
		os.Exit(1)
	}

	// Write CSR to output file
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			fmt.Sprintf("Failed to create output directory: %s", outputDir),
		}, err.Error(), true)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, []byte(csrResponse.Data.CSR), 0o644); err != nil {
		cmdCtx.printResultTable("CSR GENERATE FAILED", []string{
			fmt.Sprintf("Failed to write CSR to file: %s", outputPath),
		}, err.Error(), true)
		os.Exit(1)
	}

	// Display result
	commonName := fmt.Sprintf("%v", config["common_name"])
	keyType := fmt.Sprintf("%v", config["key_type"])
	keyBits := fmt.Sprintf("%v", config["key_bits"])

	cmdCtx.printResultTable("CSR GENERATE SUCCESS", []string{
		fmt.Sprintf(
			"Engine:      %s\n"+
				"Common Name: %s\n"+
				"Key ID:      %s\n"+
				"Key Type:    %s (%s bits)\n"+
				"Output:      %s",
			engineName, commonName, csrResponse.Data.KeyID, keyType, keyBits, outputPath),
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultEngineGenerateRootInternalCmd(cmd *cobra.Command, args []string) error {
	// Validate required flags
	engineName := cmdCtx.cfg.GetString("engine.name")
	if engineName == "" {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			"Engine name is required (--engine / -e)",
		}, "", true)
		os.Exit(1)
	}

	outputPath := cmdCtx.cfg.GetString("csr.output")
	if outputPath == "" {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			"Output file is required (--output / -o)",
		}, "", true)
		os.Exit(1)
	}

	cmdCtx.LogVerbose("Engine: %s, Output: %s", engineName, outputPath)

	// Create authenticated Vault client
	client, vaultToken, err := cmdCtx.newAuthenticatedVaultClient()
	if err != nil {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			err.Error(),
		}, "", true)
		os.Exit(1)
	}

	// Build cascading config: defaults → config file → inline config → --cn flag
	config := map[string]interface{}{
		"key_type":     "rsa",
		"key_bits":     4096,
		"format":       "pem",
		"ttl":          "87600h",
		"organization": "Akashic",
		"ou":           "Security",
		"country":      "US",
	}

	configFilePath := cmdCtx.cfg.GetString("engine.config_file")
	if configFilePath != "" {
		fileBytes, err := os.ReadFile(configFilePath)
		if err != nil {
			cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
				fmt.Sprintf("Failed to read config file: %s", configFilePath),
			}, err.Error(), true)
			os.Exit(1)
		}
		var fileConfig map[string]interface{}
		if err := json.Unmarshal(fileBytes, &fileConfig); err != nil {
			cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
				"Failed to parse config file (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range fileConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from file: %s", configFilePath)
	}

	inlineConfig := cmdCtx.cfg.GetString("engine.config")
	if inlineConfig != "" {
		var parsedConfig map[string]interface{}
		if err := json.Unmarshal([]byte(inlineConfig), &parsedConfig); err != nil {
			cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
				"Failed to parse inline config (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range parsedConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from inline flag")
	}

	// --cn flag has highest priority
	cnFlag := cmdCtx.cfg.GetString("csr.common_name")
	if cnFlag != "" {
		config["common_name"] = cnFlag
	}

	// Validate common_name is present
	if _, ok := config["common_name"]; !ok {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			"common_name is required (use --cn or include in config file/inline)",
		}, "", true)
		os.Exit(1)
	}
	if cn, ok := config["common_name"].(string); ok && cn == "" {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			"common_name cannot be empty",
		}, "", true)
		os.Exit(1)
	}

	// Send root CA generation request
	apiPath := fmt.Sprintf("/v1/%s/root/generate/internal", engineName)
	cmdCtx.LogVerbose("Generating root CA: POST %s", apiPath)

	resp, body, err := client.SendRequestWithToken(http.MethodPost, apiPath, config, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			"Failed to send root CA generation request",
		}, err.Error(), true)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			fmt.Sprintf("Vault returned status %d", resp.StatusCode),
			string(body),
		}, "", true)
		os.Exit(1)
	}

	// Parse response
	var rootResponse struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
			KeyID       string `json:"key_id"`
			SerialNum   string `json:"serial_number"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &rootResponse); err != nil {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			"Failed to parse root CA response",
		}, err.Error(), true)
		os.Exit(1)
	}

	if rootResponse.Data.Certificate == "" {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			"Certificate not found in Vault response",
		}, string(body), true)
		os.Exit(1)
	}

	// Write certificate to output file
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			fmt.Sprintf("Failed to create output directory: %s", outputDir),
		}, err.Error(), true)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, []byte(rootResponse.Data.Certificate), 0o644); err != nil {
		cmdCtx.printResultTable("ROOT GENERATE FAILED", []string{
			fmt.Sprintf("Failed to write certificate to file: %s", outputPath),
		}, err.Error(), true)
		os.Exit(1)
	}

	// Display result
	commonName := fmt.Sprintf("%v", config["common_name"])
	keyType := fmt.Sprintf("%v", config["key_type"])
	keyBits := fmt.Sprintf("%v", config["key_bits"])
	ttl := fmt.Sprintf("%v", config["ttl"])

	cmdCtx.printResultTable("ROOT GENERATE SUCCESS", []string{
		fmt.Sprintf(
			"Engine:      %s\n"+
				"Common Name: %s\n"+
				"Key ID:      %s\n"+
				"Serial:      %s\n"+
				"Key Type:    %s (%s bits)\n"+
				"TTL:         %s\n"+
				"Output:      %s",
			engineName, commonName, rootResponse.Data.KeyID, rootResponse.Data.SerialNum, keyType, keyBits, ttl, outputPath),
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultEngineSignIntermediateCmd(cmd *cobra.Command, args []string) error {
	// Validate required flags
	engineName := cmdCtx.cfg.GetString("engine.name")
	if engineName == "" {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			"Signing engine is required (--engine / -e)",
		}, "", true)
		os.Exit(1)
	}

	csrInputPath := cmdCtx.cfg.GetString("sign.csr_input")
	if csrInputPath == "" {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			"CSR input file is required (--csr)",
		}, "", true)
		os.Exit(1)
	}

	outputPath := cmdCtx.cfg.GetString("csr.output")
	if outputPath == "" {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			"Output file is required (--output / -o)",
		}, "", true)
		os.Exit(1)
	}

	cmdCtx.LogVerbose("Signing engine: %s, CSR: %s, Output: %s", engineName, csrInputPath, outputPath)

	// Read CSR file
	csrBytes, err := os.ReadFile(csrInputPath)
	if err != nil {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			fmt.Sprintf("Failed to read CSR file: %s", csrInputPath),
		}, err.Error(), true)
		os.Exit(1)
	}
	csrPEM := string(csrBytes)

	// Create authenticated Vault client
	client, vaultToken, err := cmdCtx.newAuthenticatedVaultClient()
	if err != nil {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			err.Error(),
		}, "", true)
		os.Exit(1)
	}

	// Build cascading config: defaults → config file → inline config → --cn flag
	config := map[string]interface{}{
		"use_csr_values": true,
		"format":         "pem_bundle",
		"ttl":            "43800h",
	}

	configFilePath := cmdCtx.cfg.GetString("engine.config_file")
	if configFilePath != "" {
		fileBytes, err := os.ReadFile(configFilePath)
		if err != nil {
			cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
				fmt.Sprintf("Failed to read config file: %s", configFilePath),
			}, err.Error(), true)
			os.Exit(1)
		}
		var fileConfig map[string]interface{}
		if err := json.Unmarshal(fileBytes, &fileConfig); err != nil {
			cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
				"Failed to parse config file (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range fileConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from file: %s", configFilePath)
	}

	inlineConfig := cmdCtx.cfg.GetString("engine.config")
	if inlineConfig != "" {
		var parsedConfig map[string]interface{}
		if err := json.Unmarshal([]byte(inlineConfig), &parsedConfig); err != nil {
			cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
				"Failed to parse inline config (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range parsedConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from inline flag")
	}

	// --cn flag has highest priority
	cnFlag := cmdCtx.cfg.GetString("csr.common_name")
	if cnFlag != "" {
		config["common_name"] = cnFlag
	}

	// Inject CSR into the request payload
	config["csr"] = csrPEM

	// If use_csr_values is true and no common_name provided, Vault will use CSR's CN
	// If use_csr_values is false, common_name is required
	useCsrValues, _ := config["use_csr_values"].(bool)
	if !useCsrValues {
		if _, ok := config["common_name"]; !ok {
			cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
				"common_name is required when use_csr_values is false (use --cn or include in config)",
			}, "", true)
			os.Exit(1)
		}
	}

	// Send sign-intermediate request
	apiPath := fmt.Sprintf("/v1/%s/root/sign-intermediate", engineName)
	cmdCtx.LogVerbose("Signing intermediate: POST %s", apiPath)

	resp, body, err := client.SendRequestWithToken(http.MethodPost, apiPath, config, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			"Failed to send sign-intermediate request",
		}, err.Error(), true)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			fmt.Sprintf("Vault returned status %d", resp.StatusCode),
			string(body),
		}, "", true)
		os.Exit(1)
	}

	// Parse response
	var signResponse struct {
		Data struct {
			Certificate  string   `json:"certificate"`
			IssuingCA    string   `json:"issuing_ca"`
			CAChain      []string `json:"ca_chain"`
			SerialNumber string   `json:"serial_number"`
			Expiration   int64    `json:"expiration"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &signResponse); err != nil {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			"Failed to parse sign response",
		}, err.Error(), true)
		os.Exit(1)
	}

	if signResponse.Data.Certificate == "" {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			"Signed certificate not found in Vault response",
		}, string(body), true)
		os.Exit(1)
	}

	// Write signed certificate to output file
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			fmt.Sprintf("Failed to create output directory: %s", outputDir),
		}, err.Error(), true)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, []byte(signResponse.Data.Certificate), 0o644); err != nil {
		cmdCtx.printResultTable("SIGN INTERMEDIATE FAILED", []string{
			fmt.Sprintf("Failed to write certificate to file: %s", outputPath),
		}, err.Error(), true)
		os.Exit(1)
	}

	// Display result
	ttl := fmt.Sprintf("%v", config["ttl"])
	cmdCtx.printResultTable("SIGN INTERMEDIATE SUCCESS", []string{
		fmt.Sprintf(
			"Signing Engine: %s\n"+
				"Serial:         %s\n"+
				"TTL:            %s\n"+
				"CSR Input:      %s\n"+
				"Output:         %s",
			engineName, signResponse.Data.SerialNumber, ttl, csrInputPath, outputPath),
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultEngineRegisterCmd(cmd *cobra.Command, args []string) error {
	// Validate required flags
	engineName := cmdCtx.cfg.GetString("engine.name")
	if engineName == "" {
		cmdCtx.printResultTable("REGISTER FAILED", []string{
			"Engine name is required (--engine / -e)",
		}, "", true)
		os.Exit(1)
	}

	certInputPath := cmdCtx.cfg.GetString("register.cert_input")
	if certInputPath == "" {
		cmdCtx.printResultTable("REGISTER FAILED", []string{
			"Certificate file is required (--cert)",
		}, "", true)
		os.Exit(1)
	}

	cmdCtx.LogVerbose("Engine: %s, Certificate: %s", engineName, certInputPath)

	// Read certificate file
	certBytes, err := os.ReadFile(certInputPath)
	if err != nil {
		cmdCtx.printResultTable("REGISTER FAILED", []string{
			fmt.Sprintf("Failed to read certificate file: %s", certInputPath),
		}, err.Error(), true)
		os.Exit(1)
	}
	certPEM := string(certBytes)

	// Create authenticated Vault client
	client, vaultToken, err := cmdCtx.newAuthenticatedVaultClient()
	if err != nil {
		cmdCtx.printResultTable("REGISTER FAILED", []string{
			err.Error(),
		}, "", true)
		os.Exit(1)
	}

	// Send set-signed request
	apiPath := fmt.Sprintf("/v1/%s/intermediate/set-signed", engineName)
	cmdCtx.LogVerbose("Registering certificate: POST %s", apiPath)

	payload := map[string]interface{}{
		"certificate": certPEM,
	}

	resp, body, err := client.SendRequestWithToken(http.MethodPost, apiPath, payload, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("REGISTER FAILED", []string{
			"Failed to send set-signed request",
		}, err.Error(), true)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		cmdCtx.printResultTable("REGISTER FAILED", []string{
			fmt.Sprintf("Vault returned status %d", resp.StatusCode),
			string(body),
		}, "", true)
		os.Exit(1)
	}

	// Parse response for issuer info
	var registerResponse struct {
		Data struct {
			ImportedIssuers []string `json:"imported_issuers"`
			ImportedKeys    []string `json:"imported_keys"`
			ExistingIssuers []string `json:"existing_issuers"`
			ExistingKeys    []string `json:"existing_keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &registerResponse); err != nil {
		// Non-fatal — some Vault versions return minimal response for set-signed
		cmdCtx.LogVerbose("Could not parse detailed response: %v", err)
	}

	// Display result
	details := fmt.Sprintf("Engine: %s\nCertificate: %s", engineName, certInputPath)
	if len(registerResponse.Data.ImportedIssuers) > 0 {
		details += fmt.Sprintf("\nImported Issuers: %v", registerResponse.Data.ImportedIssuers)
	}
	if len(registerResponse.Data.ExistingIssuers) > 0 {
		details += fmt.Sprintf("\nExisting Issuers: %v", registerResponse.Data.ExistingIssuers)
	}

	cmdCtx.printResultTable("REGISTER SUCCESS", []string{
		details,
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultEngineConfigUrlsCmd(cmd *cobra.Command, args []string) error {
	// Validate required flags
	engineName := cmdCtx.cfg.GetString("engine.name")
	if engineName == "" {
		cmdCtx.printResultTable("CONFIG URLS FAILED", []string{
			"Engine name is required (--engine / -e)",
		}, "", true)
		os.Exit(1)
	}

	cmdCtx.LogVerbose("Engine: %s", engineName)

	// Create authenticated Vault client
	client, vaultToken, err := cmdCtx.newAuthenticatedVaultClient()
	if err != nil {
		cmdCtx.printResultTable("CONFIG URLS FAILED", []string{
			err.Error(),
		}, "", true)
		os.Exit(1)
	}

	// Build cascading config: defaults (auto-generated from engine name + base URL) → file → inline
	baseUrl := strings.TrimSuffix(cmdCtx.cfg.GetString("pki.crl_base_url"), "/")
	if baseUrl == "" {
		baseUrl = "http://localhost:8280"
	}
	config := map[string]interface{}{
		"issuing_certificates":    []string{fmt.Sprintf("%s/v1/%s/ca", baseUrl, engineName)},
		"crl_distribution_points": []string{fmt.Sprintf("%s/v1/%s/crl", baseUrl, engineName)},
	}

	configFilePath := cmdCtx.cfg.GetString("engine.config_file")
	if configFilePath != "" {
		fileBytes, err := os.ReadFile(configFilePath)
		if err != nil {
			cmdCtx.printResultTable("CONFIG URLS FAILED", []string{
				fmt.Sprintf("Failed to read config file: %s", configFilePath),
			}, err.Error(), true)
			os.Exit(1)
		}
		var fileConfig map[string]interface{}
		if err := json.Unmarshal(fileBytes, &fileConfig); err != nil {
			cmdCtx.printResultTable("CONFIG URLS FAILED", []string{
				"Failed to parse config file (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range fileConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from file: %s", configFilePath)
	}

	inlineConfig := cmdCtx.cfg.GetString("engine.config")
	if inlineConfig != "" {
		var parsedConfig map[string]interface{}
		if err := json.Unmarshal([]byte(inlineConfig), &parsedConfig); err != nil {
			cmdCtx.printResultTable("CONFIG URLS FAILED", []string{
				"Failed to parse inline config (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range parsedConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from inline flag")
	}

	// Send config/urls request
	apiPath := fmt.Sprintf("/v1/%s/config/urls", engineName)
	cmdCtx.LogVerbose("Configuring URLs: POST %s", apiPath)

	resp, body, err := client.SendRequestWithToken(http.MethodPost, apiPath, config, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("CONFIG URLS FAILED", []string{
			"Failed to send config/urls request",
		}, err.Error(), true)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		cmdCtx.printResultTable("CONFIG URLS FAILED", []string{
			fmt.Sprintf("Vault returned status %d", resp.StatusCode),
			string(body),
		}, "", true)
		os.Exit(1)
	}

	// Display result
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	cmdCtx.printResultTable("CONFIG URLS SUCCESS", []string{
		fmt.Sprintf("Engine: %s\nURLs configured:\n%s", engineName, string(configJSON)),
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultEngineRoleCreateCmd(cmd *cobra.Command, args []string) error {
	roleName := args[0]

	engineName := cmdCtx.cfg.GetString("engine.name")
	if engineName == "" {
		cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
			"Engine name is required (--engine / -e)",
		}, "", true)
		os.Exit(1)
	}

	cmdCtx.LogVerbose("Engine: %s, Role: %s", engineName, roleName)

	// Create authenticated Vault client
	client, vaultToken, err := cmdCtx.newAuthenticatedVaultClient()
	if err != nil {
		cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
			err.Error(),
		}, "", true)
		os.Exit(1)
	}

	// Build config from file and/or inline (no defaults — must be explicit)
	config := map[string]interface{}{}

	configFilePath := cmdCtx.cfg.GetString("engine.config_file")
	if configFilePath != "" {
		fileBytes, err := os.ReadFile(configFilePath)
		if err != nil {
			cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
				fmt.Sprintf("Failed to read config file: %s", configFilePath),
			}, err.Error(), true)
			os.Exit(1)
		}
		var fileConfig map[string]interface{}
		if err := json.Unmarshal(fileBytes, &fileConfig); err != nil {
			cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
				"Failed to parse config file (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range fileConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from file: %s", configFilePath)
	}

	inlineConfig := cmdCtx.cfg.GetString("engine.config")
	if inlineConfig != "" {
		var parsedConfig map[string]interface{}
		if err := json.Unmarshal([]byte(inlineConfig), &parsedConfig); err != nil {
			cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
				"Failed to parse inline config (must be valid JSON)",
			}, err.Error(), true)
			os.Exit(1)
		}
		for k, v := range parsedConfig {
			config[k] = v
		}
		cmdCtx.LogVerbose("Config merged from inline flag")
	}

	if len(config) == 0 {
		cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
			"Role configuration is required (use --config-file / -f or --config)",
		}, "", true)
		os.Exit(1)
	}

	// Send role creation request
	apiPath := fmt.Sprintf("/v1/%s/roles/%s", engineName, roleName)
	cmdCtx.LogVerbose("Creating role: POST %s", apiPath)

	resp, body, err := client.SendRequestWithToken(http.MethodPost, apiPath, config, vaultToken)
	if err != nil {
		cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
			"Failed to send role creation request",
		}, err.Error(), true)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		cmdCtx.printResultTable("ROLE CREATE FAILED", []string{
			fmt.Sprintf("Vault returned status %d", resp.StatusCode),
			string(body),
		}, "", true)
		os.Exit(1)
	}

	configJSON, _ := json.MarshalIndent(config, "", "  ")
	cmdCtx.printResultTable("ROLE CREATE SUCCESS", []string{
		fmt.Sprintf("Engine: %s\nRole:   %s\nConfig:\n%s", engineName, roleName, string(configJSON)),
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}
