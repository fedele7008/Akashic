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
	printResult := func(title string, data []string, footer string, isErr bool) {
		termWith, _, err := term.GetSize(int(syscall.Stdout))
		if err != nil {
			cmdCtx.LogVerbose("Failed to get terminal size: %v", err)
			termWith = 80
		} else {
			termWith -= 8 // Give some space for better readability
		}
		renderer := renderer.NewColorized(
			renderer.ColorizedConfig{
				Settings: tw.Settings{
					Separators: tw.Separators{
						BetweenRows: tw.On,
					},
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
			tablewriter.WithRenderer(renderer),
			tablewriter.WithRowConfig(rowCfg),
			tablewriter.WithFooterConfig(footerCfg),
		)

		table.Header(title)
		table.Bulk(data)
		table.Footer(footer)
		table.Render()
	}
	address := cmdCtx.cfg.GetString("vault.address")
	if address == "" {
		printResult("VAULT STATUS FAILED", []string{
			"Vault address is not specified",
		}, "", true)
		os.Exit(1)
	}
	tlsConfig, err := getVaultTlsConfig(cmdCtx)
	if err != nil {
		printResult("VAULT STATUS FAILED", []string{
			"Failed to create TLS configuration",
		}, err.Error(), true)
		os.Exit(1)
	}
	client, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		printResult("VAULT STATUS FAILED", []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}

	resp, body, err := client.SendRequest(http.MethodGet, "/v1/sys/health", nil)
	if err != nil {
		printResult("VAULT STATUS FAILED", []string{
			"Failed to get Vault status",
		}, err.Error(), true)
		os.Exit(1)
	}

	output, err := common.ConvJsonToYaml(body)
	if err != nil {
		printResult("VAULT STATUS FAILED", []string{
			"failed to convert JSON to YAML",
		}, err.Error(), true)
		os.Exit(1)
	}

	output = strings.TrimSuffix(output, "\n")
	printResult("VAULT STATUS RESULT", []string{
		output,
	}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunPkiVaultInitCmd(cmd *cobra.Command, args []string) error {
	printResult := func(title string, data []string, footer string, isErr bool) {
		termWidth, _, err := term.GetSize(int(syscall.Stdout))
		if err != nil {
			cmdCtx.LogVerbose("Failed to get terminal size: %v", err)
			termWidth = 80
		} else {
			termWidth -= 8 // Give some space for better readability
		}
		renderer := renderer.NewColorized(
			renderer.ColorizedConfig{
				Settings: tw.Settings{
					Separators: tw.Separators{
						BetweenRows: tw.On,
					},
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
				AutoWrap: tw.WrapBreak,
			},
			Padding: tw.CellPadding{
				Global: tw.Padding{
					Right: " ",
					Left:  " ",
				},
			},
			ColMaxWidths: tw.CellWidth{Global: termWidth},
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
			ColMaxWidths: tw.CellWidth{Global: termWidth},
		}
		table := tablewriter.NewTable(os.Stdout,
			tablewriter.WithRenderer(renderer),
			tablewriter.WithRowConfig(rowCfg),
			tablewriter.WithFooterConfig(footerCfg),
		)

		table.Header(title)
		table.Bulk(data)
		table.Footer(footer)
		table.Render()
	}
	address := cmdCtx.cfg.GetString("vault.address")
	if address == "" {
		printResult("VAULT INIT FAILED", []string{
			"Vault address is not specified",
		}, "", true)
		os.Exit(1)
	}
	tlsConfig, err := getVaultTlsConfig(cmdCtx)
	if err != nil {
		printResult("VAULT INIT FAILED", []string{
			"Failed to create TLS configuration",
		}, err.Error(), true)
		os.Exit(1)
	}
	getClient, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		printResult("VAULT INIT FAILED", []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}
	resp, body, err := getClient.SendRequest(http.MethodGet, "/v1/sys/init", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		printResult("VAULT INIT FAILED", []string{
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
		printResult("VAULT INIT FAILED", []string{
			"Unable to parse init response",
		}, err.Error(), true)
		os.Exit(1)
	}
	if initResp.Initialized {
		printResult("VAULT INIT SUCCESS", []string{
			"Vault is already initialized!",
		}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)
		os.Exit(0)
	}
	override := cmdCtx.cfg.GetBool("vault.init.file_override")
	numKey := cmdCtx.cfg.GetInt("vault.keys")
	if numKey < 1 {
		printResult("VAULT INIT FAILED", []string{
			"Wrong number of keys specified",
		}, "number of keys must be greater than 0", true)
		os.Exit(1)
	}
	numThreshold := cmdCtx.cfg.GetInt("vault.thresholds")
	if numThreshold < 1 || numThreshold > numKey {
		printResult("VAULT INIT FAILED", []string{
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
			printResult("VAULT INIT FAILED", []string{
				"Failed to get key output directory info",
			}, err.Error(), true)
			os.Exit(1)
		} else if !info.IsDir() {
			printResult("VAULT INIT FAILED", []string{
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
				printResult("VAULT INIT FAILED", []string{
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
				printResult("VAULT INIT FAILED", []string{
					"Failed to get key output file info",
				}, err.Error(), true)
				os.Exit(1)
			}
		} else if info.IsDir() {
			printResult("VAULT INIT FAILED", []string{
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
				printResult("VAULT INIT FAILED", []string{
					"Failed to get root output directory info",
				}, err.Error(), true)
				os.Exit(1)
			}
		} else if info.IsDir() {
			printResult("VAULT INIT FAILED", []string{
				"Something went wrong while verifying root output file",
			}, fmt.Sprintf("root output file should not be a directory: %s", rootFile), true)
			os.Exit(1)
		} else {
			// confirm overwrite
			absPath, err := filepath.Abs(rootFile)
			if err != nil {
				printResult("VAULT INIT FAILED", []string{
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
				printResult("VAULT INIT FAILED", []string{
					"Something went wrong while reading passphrase",
				}, err.Error(), true)
				os.Exit(1)
			}
			secret = string(passphraseBytes)

			fmt.Print("Confirm passphrase: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				printResult("VAULT INIT FAILED", []string{
					"Something went wrong while reading passphrase confirmation",
				}, err.Error(), true)
				os.Exit(1)
			}
			if string(confirmBytes) != secret {
				printResult("VAULT INIT FAILED", []string{
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
		printResult("VAULT INIT FAILED", []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}

	resp, body, err = postClient.SendRequest(http.MethodPost, "/v1/sys/init", jsonPayload)
	if err != nil {
		printResult("VAULT INIT FAILED", []string{
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
		printResult("VAULT INIT FAILED", []string{
			"Something went wrong while parsing initialization response",
			"You might need to reset the vault data volume and try again.",
		}, err.Error(), true)
		os.Exit(1)
	}
	if len(initResponse.Keys) != numKey {
		printResult("VAULT INIT FAILED", []string{
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
				printResult("VAULT INIT FAILED", []string{
					"Something went wrong while issuing secure token",
					"You might need to reset the vault data volume and try again.",
				}, err.Error(), true)
				os.Exit(1)
			}
			keyEncData[i] = token
		}

		if mkdirCallback != nil {
			if err := mkdirCallback(); err != nil {
				printResult("VAULT INIT FAILED", []string{
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
				printResult("VAULT INIT FAILED", []string{
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
			printResult("VAULT INIT FAILED", []string{
				"Something went wrong while issuing secure token",
				"You might need to reset the vault data volume and try again.",
			}, err.Error(), true)
			os.Exit(1)
		}
		if mkrootCallback == nil {
			printResult("VAULT INIT FAILED", []string{
				"Assertion failed",
				"You might need to reset the vault data volume and try again.",
			}, "root secure token file creation callback is missing", true)
			os.Exit(1)
		}
		if err := mkrootCallback([]byte(secureRootToken)); err != nil {
			printResult("VAULT INIT FAILED", []string{
				"Something went wrong while creating root secure token file",
				"You might need to reset the vault data volume and try again.",
			}, err.Error(), true)
			os.Exit(1)
		}
		rootStr += fmt.Sprintf("- Root token saved to: %s (encrypted)\n", rootFile)
	}
	reportBody = append(reportBody, rootStr)

	printResult("VAULT INIT RESULT", reportBody, fmt.Sprintf("Status code: %d", resp.StatusCode), false)

	return nil
}

func (cmdCtx *CliContext) RunTokenInspectCmd(cmd *cobra.Command, args []string) error {
	min := cmdCtx.cfg.GetBool("min_out")

	// Get secret passphrase to decrypt token
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
			if min {
				os.Exit(1)
			}
			return fmt.Errorf("failed to read passphrase: %v", err)
		}
		secret = string(passphraseBytes)
	}
	secret = strings.TrimSpace(secret)

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
	printResult := func(title string, data []string, footer string, isErr bool) {
		termWidth, _, err := term.GetSize(int(syscall.Stdout))
		if err != nil {
			cmdCtx.LogVerbose("Failed to get terminal size: %v", err)
			termWidth = 80
		} else {
			termWidth -= 8 // Give some space for better readability
		}
		renderer := renderer.NewColorized(
			renderer.ColorizedConfig{
				Settings: tw.Settings{
					Separators: tw.Separators{
						BetweenRows: tw.On,
					},
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
				AutoWrap: tw.WrapBreak,
			},
			Padding: tw.CellPadding{
				Global: tw.Padding{
					Right: " ",
					Left:  " ",
				},
			},
			ColMaxWidths: tw.CellWidth{Global: termWidth},
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
			ColMaxWidths: tw.CellWidth{Global: termWidth},
		}
		table := tablewriter.NewTable(os.Stdout,
			tablewriter.WithRenderer(renderer),
			tablewriter.WithRowConfig(rowCfg),
			tablewriter.WithFooterConfig(footerCfg),
		)

		table.Header(title)
		table.Bulk(data)
		table.Footer(footer)
		table.Render()
	}
	const (
		resultTitle       = "VAULT UNSEAL RESULT"
		failedTitle       = "VAULT UNSEAL FAILED"
		requestEndpoint   = "/v1/sys/unseal"
		statusEndpoint    = "/v1/sys/health"
		GlobSearchTimeout = 5 * time.Second
	)
	type unsealReqJsonPayload struct {
		Key string `json:"key"`
	}
	address := cmdCtx.cfg.GetString("vault.address")
	if address == "" {
		printResult(failedTitle, []string{
			"Vault address is not specified",
		}, "", true)
		os.Exit(1)
	}
	tlsConfig, err := getVaultTlsConfig(cmdCtx)
	if err != nil {
		printResult(failedTitle, []string{
			"Failed to create TLS configuration",
		}, err.Error(), true)
		os.Exit(1)
	}
	client, err := NewHttpClient(cmdCtx, address, tlsConfig)
	if err != nil {
		printResult(failedTitle, []string{
			"Failed to create HTTP client",
		}, err.Error(), true)
		os.Exit(1)
	}
	resp, body, err := client.SendRequest(http.MethodGet, statusEndpoint, nil)
	if err != nil {
		printResult(failedTitle, []string{
			"Failed to get vault status",
		}, err.Error(), true)
		os.Exit(1)
	}
	var jsonStatus any
	err = json.Unmarshal(body, &jsonStatus)
	if err != nil {
		printResult(failedTitle, []string{
			"Failed to parse vault status response",
		}, err.Error(), true)
		os.Exit(1)
	}
	jsonStatusMap, ok := jsonStatus.(map[string]any)
	if !ok {
		printResult(failedTitle, []string{
			"Failed to convert vault status response to map",
		}, "", true)
		os.Exit(1)
	}
	isSealedRaw, ok := jsonStatusMap["sealed"]
	if !ok {
		printResult(failedTitle, []string{
			"Failed to find 'sealed' key in vault status response",
		}, "", true)
		os.Exit(1)
	}
	isSealed, ok := isSealedRaw.(bool)
	if !ok {
		printResult(failedTitle, []string{
			"Failed to convert 'sealed' value to boolean",
		}, "", true)
		os.Exit(1)
	}
	if !isSealed {
		printResult(resultTitle, []string{
			"Vault is not sealed",
		}, fmt.Sprintf("Status code: %d", resp.StatusCode), false)
		return nil
	}

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
				printResult(failedTitle, []string{
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
					printResult(failedTitle, []string{
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
				printResult(failedTitle, []string{
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
				printResult(failedTitle, []string{
					"Failed to read passphrase",
				}, err.Error(), true)
				os.Exit(1)
			}
			secret = strings.TrimSpace(string(passphraseBytes))
		}
	}

	type unsealKeyResult struct {
		Key          string
		Source       string
		IsUsed       bool
		IsFailed     bool
		Result       string
		ResultDetail string
		ExecuteOrder int
		IsClean      bool
	}
	unsealKeys := []*unsealKeyResult{}
	for i, arg := range args {
		unsealKeys = append(unsealKeys, &unsealKeyResult{
			Key:    arg,
			Source: fmt.Sprintf("ARG[%d]", i),
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
		unsealKeys = append(unsealKeys, &unsealKeyResult{
			Key:    string(data),
			Source: fmt.Sprintf("FILE: \"%s\"", file),
		})
	}

	if len(unsealKeys) == 0 {
		printResult(failedTitle, []string{
			"No valid unseal key found",
		}, "", true)
		os.Exit(1)
	}

	// TESTING CODE STARTS
	unsealKeys = []*unsealKeyResult{
		{Key: "51eeb5cb4cd51f2ef1c281b441f71420f8c99ce37182cb76948cc6d0c231bcba1a", Source: "(WRONG BUT ACCEPTS)"},
		{Key: "51eeb5cb4cd51f2ef1c281b441f71420f8c99ce37182cb76948cc6d0c231bcba1f", Source: "(CORRECT 1)"},
		{Key: "399e4971ad200094a9180c1ec7c2a6c3ccfc2e47a046ee2e4499caba98faab26f2", Source: "(WRONG BUT ACCEPTS)"},
		{Key: "399e4971ad200094a9180c1ec7c2a6c3ccfc2e47a046ee2e4499caba98faab26f6", Source: "(CORRECT 2)"},
		{Key: "6641248f0b2bb9468d62734c61f6b50b62c72654c42982de6e5afa49c0be9861ea", Source: "(WRONG BUT ACCEPTS)"},
		{Key: "6641248f0b2bb9468d62734c61f6b50b62c72654c42982de6e5afa49c0be9861e2", Source: "(CORRECT 3)"},
		{Key: "b56f7379bc94c781f707f67d4c45ae378fb4e69557c1452f28bf5d0fa34c8dfa14", Source: "(CORRECT 4)"},
	}
	// TESTING CODE ENDS

	cmdCtx.LogVerbose("Start unsealing...")

	setDirtyBits := func(keys []*unsealKeyResult) {
		for _, e := range keys {
			if e.IsFailed {
				continue
			}
			e.IsClean = false
		}
	}
	type unsealRspJsonPayload struct {
		Errs      []string `json:"errors"`
		Sealed    bool     `json:"sealed"`
		Threshold int      `json:"t"`
		TotalKeys int      `json:"n"`
		Progress  int      `json:"progress"`
	}
	i := 0
	failCount := 0
	threshold := -1
	const (
		processing = 0
		failed     = 1
		success    = 2
	)
	status := processing
	var lastSuccessfulCleanUnsealRespJsonPayload *unsealRspJsonPayload
	setDirtyBits(unsealKeys)
	for {
		// successed not failed, clean ones
		cleanAcceptedCount := 0
		for _, e := range unsealKeys {
			if e.IsUsed && !e.IsFailed && e.IsClean {
				cleanAcceptedCount++
			}
		}
		// fail detection
		if failCount+cleanAcceptedCount >= len(unsealKeys) {
			status = failed
			cmdCtx.LogVerbose("Unseal process failed")
			break
		}

		// Don't spam Vault unseal API too often
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		idx := i % len(unsealKeys)
		i++
		keyEntity := unsealKeys[idx]

		// If already failed, skip this key
		if keyEntity.IsFailed {
			cmdCtx.LogVerbose("Skipping unseal key %s (already failed)", keyEntity.Key)
			failCount++
			continue
		}

		// If already got accepted and it's still recorded in vault, skip this key
		if keyEntity.IsClean {
			cmdCtx.LogVerbose("Skipping unseal key %s (already accepted)", keyEntity.Key)
			continue
		}
		cmdCtx.LogVerbose("Trying to unseal with key %s", keyEntity.Key)

		keyEntity.IsUsed = true
		_, data, err := client.SendRequest(http.MethodPost, requestEndpoint, unsealReqJsonPayload{
			Key: keyEntity.Key,
		})

		if err != nil {
			cmdCtx.LogVerbose("Request send failed")
			keyEntity.Result = "Failed to send request"
			keyEntity.ResultDetail = err.Error()
			keyEntity.IsFailed = true
			failCount++
			setDirtyBits(unsealKeys)
			lastSuccessfulCleanUnsealRespJsonPayload = nil
			continue
		}

		jsonRespBody := unsealRspJsonPayload{}
		if err := json.Unmarshal(data, &jsonRespBody); err != nil {
			cmdCtx.LogVerbose("Response parsing failed")
			keyEntity.Result = "Failed to parse response"
			keyEntity.ResultDetail = err.Error()
			keyEntity.IsFailed = true
			failCount++
			setDirtyBits(unsealKeys)
			lastSuccessfulCleanUnsealRespJsonPayload = nil
			continue
		}

		if jsonRespBody.Errs != nil {
			cmdCtx.LogVerbose("Unseal request rejected")
			keyEntity.Result = "Unseal request failed"
			keyEntity.ResultDetail = strings.Join(jsonRespBody.Errs, ", ")
			keyEntity.IsFailed = true
			failCount++
			setDirtyBits(unsealKeys)
			lastSuccessfulCleanUnsealRespJsonPayload = nil
			continue
		}

		cmdCtx.LogVerbose("Unseal request accepted %v", keyEntity)
		failCount = 0
		keyEntity.IsClean = true
		keyEntity.Result = "Unseal request succeeded"
		lastSuccessfulCleanUnsealRespJsonPayload = &jsonRespBody
		progress := jsonRespBody.Progress
		if jsonRespBody.Progress == 0 && !jsonRespBody.Sealed {
			// adjust progress value as it reset to 0 when vault just unsealed
			progress = jsonRespBody.Threshold
		}
		keyEntity.ResultDetail = fmt.Sprintf("Progress: %d/%d", progress, jsonRespBody.Threshold)
		keyEntity.ExecuteOrder = i
		threshold = jsonRespBody.Threshold

		// detect unseal
		if !jsonRespBody.Sealed {
			cmdCtx.LogVerbose("Vault is now unsealed")
			status = success
			break
		}
	}
	cmdCtx.LogVerbose("Unseal process result: %v", status)

	successedFiltered := []unsealKeyResult{}
	for _, e := range unsealKeys {
		if !e.IsFailed {
			successedFiltered = append(successedFiltered, *e)
		}
	}
	slices.SortFunc(successedFiltered, func(a, b unsealKeyResult) int {
		return b.ExecuteOrder - a.ExecuteOrder
	})
	appliedKeyOrders := []int{}
	for i := range threshold {
		if len(successedFiltered) <= i {
			break
		}
		appliedKeyOrders = append(appliedKeyOrders, successedFiltered[i].ExecuteOrder)
	}
	isApplied := func(unsealKeyEntity *unsealKeyResult, appliedKeyOrders []int) bool {
		return slices.Contains(appliedKeyOrders, unsealKeyEntity.ExecuteOrder)
	}

	resultBody := []string{}
	for _, e := range unsealKeys {
		var msg string
		source := color.New(color.FgCyan).Sprint(e.Source)
		if !e.IsUsed {
			msg = fmt.Sprintf(color.New(color.Reset).Sprint()+"[not used] %s", source)
		} else if e.IsFailed {
			st := color.New(color.FgRed).Sprint("rejected")
			detail := color.New(color.FgMagenta).Sprint(e.ResultDetail)
			msg = fmt.Sprintf(color.New(color.Reset).Sprint()+"[%s] %s: %s", st, source, detail)
		} else { // successed
			st := color.New(color.FgGreen).Sprint("accepted")
			detail := e.ResultDetail
			if isApplied(e, appliedKeyOrders) {
				msg = fmt.Sprintf(color.New(color.Reset).Sprint()+"[%s] %s: %s", st, source, detail)
			} else {
				msg = fmt.Sprintf(color.New(color.Reset).Sprint()+"[%s] %s", st, source)
			}
		}
		resultBody = append(resultBody, msg)
	}

	footer := ""
	if status == success {
		footer = color.New(color.FgGreen).Sprint("Vault is now unsealed")
	} else {
		if lastSuccessfulCleanUnsealRespJsonPayload != nil {
			footer = fmt.Sprintf(color.New(color.FgYellow).Sprint("Last successful progress status:")+"\n"+
				"- Total Keys exist: %d\n"+
				"- Last Progress: %d/%d",
				lastSuccessfulCleanUnsealRespJsonPayload.TotalKeys,
				lastSuccessfulCleanUnsealRespJsonPayload.Progress,
				lastSuccessfulCleanUnsealRespJsonPayload.Threshold)
		} else {
			footer = ""
		}
	}

	printResult(
		common.Ternary(status == success,
			resultTitle,
			failedTitle),
		resultBody,
		footer,
		status == failed,
	)

	return nil
}
