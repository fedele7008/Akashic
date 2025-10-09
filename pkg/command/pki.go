package command

import (
	"crypto/elliptic"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"akashic/akashic/pkg/pki"

	"github.com/spf13/cobra"
)

const (
	PKICmd      = "pki"
	PKICmdShort = "Manage PKI certificates and keys"
	PKICmdLong  = `Manage the Public Key Infrastructure (PKI) for Akashic.

The pki command allows you to generate, verify, and manage certificates and keys
for secure communication between Akashic components.

Available commands:
  init              Initialize PKI by generating the self-signed CA
  generate-server   Generate a server certificate
  generate-client   Generate a client certificate
  list              List all certificates
  verify            Verify a certificate against the CA
  check-expiry      Check certificate expiration status`
)

// NewPKICmd creates the pki command with all subcommands
func NewPKICmd() *cobra.Command {
	pkiCmd := &cobra.Command{
		Use:   PKICmd,
		Short: PKICmdShort,
		Long:  PKICmdLong,
	}

	// Add subcommands
	pkiCmd.AddCommand(newPKIInitCmd())
	pkiCmd.AddCommand(newPKIGenerateServerCmd())
	pkiCmd.AddCommand(newPKIGenerateClientCmd())
	pkiCmd.AddCommand(newPKIListCmd())
	pkiCmd.AddCommand(newPKIVerifyCmd())
	pkiCmd.AddCommand(newPKICheckExpiryCmd())

	return pkiCmd
}

// newPKIInitCmd creates the 'pki init' command
func newPKIInitCmd() *cobra.Command {
	var (
		certsDir     string
		commonName   string
		organization string
		country      string
		validityYears int
		keyType      string
		rsaKeySize   int
		ecdsaCurve   string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize PKI by generating the self-signed CA",
		Long: `Initialize the Public Key Infrastructure by generating a self-signed Certificate Authority.

This command creates the root CA certificate and private key that will be used to
sign all server and client certificates.

Example:
  akashic pki init
  akashic pki init --common-name "My Custom CA" --validity-years 5
  akashic pki init --key-type ecdsa --ecdsa-curve P-384`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if CA already exists
			caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
			caKeyPath := filepath.Join(certsDir, "ca", "ca.key")

			if pki.FileExists(caCertPath) && !force {
				return fmt.Errorf("CA already exists at %s (use --force to overwrite)", caCertPath)
			}

			// Parse key type
			var pkiKeyType pki.KeyType
			switch strings.ToLower(keyType) {
			case "rsa":
				pkiKeyType = pki.KeyTypeRSA
			case "ecdsa":
				pkiKeyType = pki.KeyTypeECDSA
			default:
				return fmt.Errorf("invalid key type: %s (must be 'rsa' or 'ecdsa')", keyType)
			}

			// Parse ECDSA curve if needed
			var curve elliptic.Curve
			if pkiKeyType == pki.KeyTypeECDSA {
				var err error
				curve, err = pki.GetECDSACurve(pki.ECDSACurve(ecdsaCurve))
				if err != nil {
					return fmt.Errorf("invalid ECDSA curve: %v", err)
				}
			}

			// Create CA options
			opts := &pki.CAOptions{
				CommonName:    commonName,
				Organization:  organization,
				Country:       country,
				ValidityYears: validityYears,
				KeyType:       pkiKeyType,
				RSAKeySize:    pki.KeySize(rsaKeySize),
				ECDSACurve:    curve,
			}

			// Generate CA
			fmt.Printf("Generating %s CA certificate...\n", keyType)
			ca, err := pki.GenerateCA(opts)
			if err != nil {
				return fmt.Errorf("failed to generate CA: %v", err)
			}

			// Save CA
			if err := pki.SaveCA(ca, caCertPath, caKeyPath); err != nil {
				return fmt.Errorf("failed to save CA: %v", err)
			}

			fmt.Printf("\n✓ CA certificate generated successfully!\n\n")
			fmt.Printf("  Certificate: %s\n", caCertPath)
			fmt.Printf("  Private Key: %s\n", caKeyPath)
			fmt.Printf("  Common Name: %s\n", commonName)
			fmt.Printf("  Validity:    %d years\n", validityYears)
			fmt.Printf("  Key Type:    %s", keyType)
			if pkiKeyType == pki.KeyTypeRSA {
				fmt.Printf(" (%d bits)\n", rsaKeySize)
			} else {
				fmt.Printf(" (%s)\n", ecdsaCurve)
			}
			fmt.Printf("\n")

			info := ca.GetInfo()
			fmt.Printf("Certificate Details:\n")
			fmt.Printf("  Serial Number: %s\n", info.SerialNumber)
			fmt.Printf("  Not Before:    %s\n", info.NotBefore.Format(time.RFC3339))
			fmt.Printf("  Not After:     %s\n", info.NotAfter.Format(time.RFC3339))
			fmt.Printf("\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "./certs", "Directory to store certificates")
	cmd.Flags().StringVar(&commonName, "common-name", "Akashic Self-Signed CA", "CA common name")
	cmd.Flags().StringVar(&organization, "organization", "Akashic", "CA organization")
	cmd.Flags().StringVar(&country, "country", "US", "CA country code")
	cmd.Flags().IntVar(&validityYears, "validity-years", 10, "CA certificate validity in years")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type (rsa or ecdsa)")
	cmd.Flags().IntVar(&rsaKeySize, "rsa-key-size", 4096, "RSA key size (2048 or 4096)")
	cmd.Flags().StringVar(&ecdsaCurve, "ecdsa-curve", "P-384", "ECDSA curve (P-256 or P-384)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing CA")

	return cmd
}

// newPKIGenerateServerCmd creates the 'pki generate-server' command
func newPKIGenerateServerCmd() *cobra.Command {
	var (
		certsDir     string
		name         string
		commonName   string
		dnsNames     []string
		ipAddresses  []string
		validityDays int
		keyType      string
		rsaKeySize   int
		ecdsaCurve   string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "generate-server",
		Short: "Generate a server certificate",
		Long: `Generate a server certificate signed by the CA.

Server certificates are used for TLS/HTTPS servers. They include DNS names
and IP addresses in the Subject Alternative Names (SANs) field.

Example:
  akashic pki generate-server --name control --dns localhost --dns control.akashic.local --ip 127.0.0.1
  akashic pki generate-server --name auth --dns localhost --ip 0.0.0.0
  akashic pki generate-server --name ldap --dns ldap --dns ldap.akashic.local`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			if len(dnsNames) == 0 {
				return fmt.Errorf("at least one --dns name is required")
			}

			// Load CA
			caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
			caKeyPath := filepath.Join(certsDir, "ca", "ca.key")

			if !pki.FileExists(caCertPath) {
				return fmt.Errorf("CA not found. Run 'akashic pki init' first")
			}

			ca, err := pki.LoadCAFromFiles(caCertPath, caKeyPath)
			if err != nil {
				return fmt.Errorf("failed to load CA: %v", err)
			}

			// Check if certificate already exists
			certPath := filepath.Join(certsDir, "servers", name+".crt")
			keyPath := filepath.Join(certsDir, "servers", name+".key")

			if pki.FileExists(certPath) && !force {
				return fmt.Errorf("certificate already exists at %s (use --force to overwrite)", certPath)
			}

			// Parse key type
			var pkiKeyType pki.KeyType
			switch strings.ToLower(keyType) {
			case "rsa":
				pkiKeyType = pki.KeyTypeRSA
			case "ecdsa":
				pkiKeyType = pki.KeyTypeECDSA
			default:
				return fmt.Errorf("invalid key type: %s (must be 'rsa' or 'ecdsa')", keyType)
			}

			// Parse ECDSA curve if needed
			var curve elliptic.Curve
			if pkiKeyType == pki.KeyTypeECDSA {
				curve, err = pki.GetECDSACurve(pki.ECDSACurve(ecdsaCurve))
				if err != nil {
					return fmt.Errorf("invalid ECDSA curve: %v", err)
				}
			}

			// Use first DNS name as common name if not specified
			if commonName == "" {
				commonName = dnsNames[0]
			}

			// Create server certificate options
			opts := &pki.ServerCertOptions{
				CA:           ca,
				CommonName:   commonName,
				Organization: "Akashic",
				Country:      "US",
				DNSNames:     dnsNames,
				IPAddresses:  ipAddresses,
				ValidityDays: validityDays,
				KeyType:      pkiKeyType,
				RSAKeySize:   pki.KeySize(rsaKeySize),
				ECDSACurve:   curve,
			}

			// Generate server certificate
			fmt.Printf("Generating server certificate for '%s'...\n", name)
			cert, err := pki.GenerateServerCertificate(opts)
			if err != nil {
				return fmt.Errorf("failed to generate server certificate: %v", err)
			}

			// Save certificate
			if err := pki.SaveCertificate(cert, certPath, keyPath); err != nil {
				return fmt.Errorf("failed to save certificate: %v", err)
			}

			fmt.Printf("\n✓ Server certificate generated successfully!\n\n")
			fmt.Printf("  Certificate: %s\n", certPath)
			fmt.Printf("  Private Key: %s\n", keyPath)
			fmt.Printf("  Common Name: %s\n", commonName)
			fmt.Printf("  DNS Names:   %s\n", strings.Join(dnsNames, ", "))
			if len(ipAddresses) > 0 {
				fmt.Printf("  IP Addresses: %s\n", strings.Join(ipAddresses, ", "))
			}
			fmt.Printf("  Validity:    %d days\n", validityDays)
			fmt.Printf("\n")

			info := cert.GetInfo()
			fmt.Printf("Certificate Details:\n")
			fmt.Printf("  Serial Number: %s\n", info.SerialNumber)
			fmt.Printf("  Not Before:    %s\n", info.NotBefore.Format(time.RFC3339))
			fmt.Printf("  Not After:     %s\n", info.NotAfter.Format(time.RFC3339))
			fmt.Printf("\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "./certs", "Directory containing certificates")
	cmd.Flags().StringVar(&name, "name", "", "Certificate name (e.g., 'control', 'auth', 'ldap') [required]")
	cmd.Flags().StringVar(&commonName, "common-name", "", "Certificate common name (defaults to first DNS name)")
	cmd.Flags().StringSliceVar(&dnsNames, "dns", nil, "DNS names for certificate (can specify multiple) [required]")
	cmd.Flags().StringSliceVar(&ipAddresses, "ip", nil, "IP addresses for certificate (can specify multiple)")
	cmd.Flags().IntVar(&validityDays, "validity-days", 365, "Certificate validity in days")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type (rsa or ecdsa)")
	cmd.Flags().IntVar(&rsaKeySize, "rsa-key-size", 2048, "RSA key size (2048 or 4096)")
	cmd.Flags().StringVar(&ecdsaCurve, "ecdsa-curve", "P-256", "ECDSA curve (P-256 or P-384)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing certificate")

	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("dns")

	return cmd
}

// newPKIGenerateClientCmd creates the 'pki generate-client' command
func newPKIGenerateClientCmd() *cobra.Command {
	var (
		certsDir     string
		name         string
		commonName   string
		email        string
		validityDays int
		keyType      string
		rsaKeySize   int
		ecdsaCurve   string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "generate-client",
		Short: "Generate a client certificate",
		Long: `Generate a client certificate signed by the CA.

Client certificates are used for mTLS authentication to the control plane.

Example:
  akashic pki generate-client --name cli --common-name "Akashic CLI Client"
  akashic pki generate-client --name bff --common-name "Akashic BFF Client" --email admin@akashic.local`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			// Load CA
			caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
			caKeyPath := filepath.Join(certsDir, "ca", "ca.key")

			if !pki.FileExists(caCertPath) {
				return fmt.Errorf("CA not found. Run 'akashic pki init' first")
			}

			ca, err := pki.LoadCAFromFiles(caCertPath, caKeyPath)
			if err != nil {
				return fmt.Errorf("failed to load CA: %v", err)
			}

			// Check if certificate already exists
			certPath := filepath.Join(certsDir, "clients", name+".crt")
			keyPath := filepath.Join(certsDir, "clients", name+".key")

			if pki.FileExists(certPath) && !force {
				return fmt.Errorf("certificate already exists at %s (use --force to overwrite)", certPath)
			}

			// Parse key type
			var pkiKeyType pki.KeyType
			switch strings.ToLower(keyType) {
			case "rsa":
				pkiKeyType = pki.KeyTypeRSA
			case "ecdsa":
				pkiKeyType = pki.KeyTypeECDSA
			default:
				return fmt.Errorf("invalid key type: %s (must be 'rsa' or 'ecdsa')", keyType)
			}

			// Parse ECDSA curve if needed
			var curve elliptic.Curve
			if pkiKeyType == pki.KeyTypeECDSA {
				curve, err = pki.GetECDSACurve(pki.ECDSACurve(ecdsaCurve))
				if err != nil {
					return fmt.Errorf("invalid ECDSA curve: %v", err)
				}
			}

			// Use name as common name if not specified
			if commonName == "" {
				commonName = "Akashic " + strings.Title(name) + " Client"
			}

			// Create client certificate options
			opts := &pki.ClientCertOptions{
				CA:           ca,
				CommonName:   commonName,
				Organization: "Akashic",
				Country:      "US",
				EmailAddress: email,
				ValidityDays: validityDays,
				KeyType:      pkiKeyType,
				RSAKeySize:   pki.KeySize(rsaKeySize),
				ECDSACurve:   curve,
			}

			// Generate client certificate
			fmt.Printf("Generating client certificate for '%s'...\n", name)
			cert, err := pki.GenerateClientCertificate(opts)
			if err != nil {
				return fmt.Errorf("failed to generate client certificate: %v", err)
			}

			// Save certificate
			if err := pki.SaveCertificate(cert, certPath, keyPath); err != nil {
				return fmt.Errorf("failed to save certificate: %v", err)
			}

			fmt.Printf("\n✓ Client certificate generated successfully!\n\n")
			fmt.Printf("  Certificate: %s\n", certPath)
			fmt.Printf("  Private Key: %s\n", keyPath)
			fmt.Printf("  Common Name: %s\n", commonName)
			if email != "" {
				fmt.Printf("  Email:       %s\n", email)
			}
			fmt.Printf("  Validity:    %d days\n", validityDays)
			fmt.Printf("\n")

			info := cert.GetInfo()
			fmt.Printf("Certificate Details:\n")
			fmt.Printf("  Serial Number: %s\n", info.SerialNumber)
			fmt.Printf("  Not Before:    %s\n", info.NotBefore.Format(time.RFC3339))
			fmt.Printf("  Not After:     %s\n", info.NotAfter.Format(time.RFC3339))
			fmt.Printf("\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "./certs", "Directory containing certificates")
	cmd.Flags().StringVar(&name, "name", "", "Certificate name (e.g., 'cli', 'bff') [required]")
	cmd.Flags().StringVar(&commonName, "common-name", "", "Certificate common name")
	cmd.Flags().StringVar(&email, "email", "", "Email address for certificate")
	cmd.Flags().IntVar(&validityDays, "validity-days", 365, "Certificate validity in days")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type (rsa or ecdsa)")
	cmd.Flags().IntVar(&rsaKeySize, "rsa-key-size", 2048, "RSA key size (2048 or 4096)")
	cmd.Flags().StringVar(&ecdsaCurve, "ecdsa-curve", "P-256", "ECDSA curve (P-256 or P-384)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing certificate")

	cmd.MarkFlagRequired("name")

	return cmd
}

// newPKIListCmd creates the 'pki list' command
func newPKIListCmd() *cobra.Command {
	var certsDir string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all certificates",
		Long: `List all certificates in the PKI directory.

This command displays information about the CA, server certificates, and client certificates.

Example:
  akashic pki list
  akashic pki list --certs-dir /path/to/certs`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("PKI Certificate Inventory\n")
			fmt.Printf("=========================\n\n")

			// List CA
			caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
			if pki.FileExists(caCertPath) {
				cert, err := pki.LoadCertificateOnly(caCertPath)
				if err != nil {
					fmt.Printf("❌ CA Certificate: ERROR - %v\n\n", err)
				} else {
					info := cert.GetInfo()
					expired := cert.IsExpired()
					expiringSoon := cert.IsExpiringSoon(30)
					daysUntil := cert.DaysUntilExpiry()

					status := "✓"
					if expired {
						status = "❌ EXPIRED"
					} else if expiringSoon {
						status = "⚠️  EXPIRING SOON"
					}

					fmt.Printf("%s CA Certificate\n", status)
					fmt.Printf("  Path:          %s\n", caCertPath)
					fmt.Printf("  Common Name:   %s\n", info.Subject)
					fmt.Printf("  Serial Number: %s\n", info.SerialNumber)
					fmt.Printf("  Not Before:    %s\n", info.NotBefore.Format("2006-01-02"))
					fmt.Printf("  Not After:     %s\n", info.NotAfter.Format("2006-01-02"))
					if !expired {
						fmt.Printf("  Days Until Expiry: %d\n", daysUntil)
					}
					fmt.Printf("\n")
				}
			} else {
				fmt.Printf("❌ CA Certificate: Not found (run 'akashic pki init')\n\n")
			}

			// List server certificates
			serversDir := filepath.Join(certsDir, "servers")
			if _, err := os.Stat(serversDir); err == nil {
				entries, err := os.ReadDir(serversDir)
				if err == nil && len(entries) > 0 {
					fmt.Printf("Server Certificates:\n")
					for _, entry := range entries {
						if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
							certPath := filepath.Join(serversDir, entry.Name())
							cert, err := pki.LoadCertificateOnly(certPath)
							if err != nil {
								fmt.Printf("  ❌ %s: ERROR - %v\n", entry.Name(), err)
								continue
							}

							info := cert.GetInfo()
							expired := cert.IsExpired()
							expiringSoon := cert.IsExpiringSoon(30)
							daysUntil := cert.DaysUntilExpiry()

							status := "✓"
							if expired {
								status = "❌"
							} else if expiringSoon {
								status = "⚠️ "
							}

							fmt.Printf("  %s %s\n", status, strings.TrimSuffix(entry.Name(), ".crt"))
							fmt.Printf("     DNS Names: %s\n", strings.Join(info.DNSNames, ", "))
							if len(info.IPAddresses) > 0 {
								fmt.Printf("     IPs:       %s\n", strings.Join(info.IPAddresses, ", "))
							}
							fmt.Printf("     Expires:   %s", info.NotAfter.Format("2006-01-02"))
							if !expired {
								fmt.Printf(" (%d days)", daysUntil)
							}
							fmt.Printf("\n")
						}
					}
					fmt.Printf("\n")
				}
			}

			// List client certificates
			clientsDir := filepath.Join(certsDir, "clients")
			if _, err := os.Stat(clientsDir); err == nil {
				entries, err := os.ReadDir(clientsDir)
				if err == nil && len(entries) > 0 {
					fmt.Printf("Client Certificates:\n")
					for _, entry := range entries {
						if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
							certPath := filepath.Join(clientsDir, entry.Name())
							cert, err := pki.LoadCertificateOnly(certPath)
							if err != nil {
								fmt.Printf("  ❌ %s: ERROR - %v\n", entry.Name(), err)
								continue
							}

							info := cert.GetInfo()
							expired := cert.IsExpired()
							expiringSoon := cert.IsExpiringSoon(30)
							daysUntil := cert.DaysUntilExpiry()

							status := "✓"
							if expired {
								status = "❌"
							} else if expiringSoon {
								status = "⚠️ "
							}

							fmt.Printf("  %s %s\n", status, strings.TrimSuffix(entry.Name(), ".crt"))
							fmt.Printf("     Common Name: %s\n", info.Subject)
							fmt.Printf("     Expires:     %s", info.NotAfter.Format("2006-01-02"))
							if !expired {
								fmt.Printf(" (%d days)", daysUntil)
							}
							fmt.Printf("\n")
						}
					}
					fmt.Printf("\n")
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "./certs", "Directory containing certificates")

	return cmd
}

// newPKIVerifyCmd creates the 'pki verify' command
func newPKIVerifyCmd() *cobra.Command {
	var (
		certsDir string
		certPath string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a certificate against the CA",
		Long: `Verify that a certificate was signed by the CA and is valid.

This command checks:
- Certificate signature (signed by CA)
- Certificate expiration
- Certificate usage (server/client)

Example:
  akashic pki verify --cert certs/servers/control.crt
  akashic pki verify --cert certs/clients/cli.crt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if certPath == "" {
				return fmt.Errorf("--cert is required")
			}

			// Load CA
			caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
			caKeyPath := filepath.Join(certsDir, "ca", "ca.key")

			if !pki.FileExists(caCertPath) {
				return fmt.Errorf("CA not found. Run 'akashic pki init' first")
			}

			ca, err := pki.LoadCAFromFiles(caCertPath, caKeyPath)
			if err != nil {
				return fmt.Errorf("failed to load CA: %v", err)
			}

			// Load certificate
			cert, err := pki.LoadCertificateOnly(certPath)
			if err != nil {
				return fmt.Errorf("failed to load certificate: %v", err)
			}

			fmt.Printf("Verifying certificate: %s\n\n", certPath)

			// Validate certificate
			if err := pki.ValidateCertificate(cert.X509Cert, ca); err != nil {
				fmt.Printf("❌ Certificate validation FAILED: %v\n", err)
				return fmt.Errorf("validation failed")
			}

			fmt.Printf("✓ Certificate is valid!\n\n")

			info := cert.GetInfo()
			fmt.Printf("Certificate Information:\n")
			fmt.Printf("  Subject:       %s\n", info.Subject)
			fmt.Printf("  Issuer:        %s\n", info.Issuer)
			fmt.Printf("  Serial Number: %s\n", info.SerialNumber)
			fmt.Printf("  Not Before:    %s\n", info.NotBefore.Format(time.RFC3339))
			fmt.Printf("  Not After:     %s\n", info.NotAfter.Format(time.RFC3339))
			fmt.Printf("  Days Until Expiry: %d\n", cert.DaysUntilExpiry())

			if len(info.DNSNames) > 0 {
				fmt.Printf("  DNS Names:     %s\n", strings.Join(info.DNSNames, ", "))
			}

			if len(info.IPAddresses) > 0 {
				fmt.Printf("  IP Addresses:  %s\n", strings.Join(info.IPAddresses, ", "))
			}

			if len(info.ExtKeyUsage) > 0 {
				fmt.Printf("  Key Usage:     %s\n", strings.Join(info.ExtKeyUsage, ", "))
			}

			fmt.Printf("\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "./certs", "Directory containing certificates")
	cmd.Flags().StringVar(&certPath, "cert", "", "Path to certificate to verify [required]")

	cmd.MarkFlagRequired("cert")

	return cmd
}

// newPKICheckExpiryCmd creates the 'pki check-expiry' command
func newPKICheckExpiryCmd() *cobra.Command {
	var (
		certsDir    string
		warningDays int
	)

	cmd := &cobra.Command{
		Use:   "check-expiry",
		Short: "Check certificate expiration status",
		Long: `Check the expiration status of all certificates.

This command scans all certificates and reports which ones are expired or
expiring soon.

Example:
  akashic pki check-expiry
  akashic pki check-expiry --warning-days 60`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Certificate Expiration Report\n")
			fmt.Printf("==============================\n")
			fmt.Printf("Warning threshold: %d days\n\n", warningDays)

			var expiredCount, expiringSoonCount, okCount int

			// Check CA
			caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
			if pki.FileExists(caCertPath) {
				cert, err := pki.LoadCertificateOnly(caCertPath)
				if err == nil {
					expired := cert.IsExpired()
					expiringSoon := cert.IsExpiringSoon(warningDays)
					daysUntil := cert.DaysUntilExpiry()

					if expired {
						fmt.Printf("❌ EXPIRED: CA Certificate (expired %d days ago)\n", -daysUntil)
						expiredCount++
					} else if expiringSoon {
						fmt.Printf("⚠️  EXPIRING SOON: CA Certificate (expires in %d days)\n", daysUntil)
						expiringSoonCount++
					} else {
						okCount++
					}
				}
			}

			// Check server certificates
			serversDir := filepath.Join(certsDir, "servers")
			if entries, err := os.ReadDir(serversDir); err == nil {
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".crt") {
						certPath := filepath.Join(serversDir, entry.Name())
						cert, err := pki.LoadCertificateOnly(certPath)
						if err != nil {
							continue
						}

						expired := cert.IsExpired()
						expiringSoon := cert.IsExpiringSoon(warningDays)
						daysUntil := cert.DaysUntilExpiry()
						name := strings.TrimSuffix(entry.Name(), ".crt")

						if expired {
							fmt.Printf("❌ EXPIRED: Server/%s (expired %d days ago)\n", name, -daysUntil)
							expiredCount++
						} else if expiringSoon {
							fmt.Printf("⚠️  EXPIRING SOON: Server/%s (expires in %d days)\n", name, daysUntil)
							expiringSoonCount++
						} else {
							okCount++
						}
					}
				}
			}

			// Check client certificates
			clientsDir := filepath.Join(certsDir, "clients")
			if entries, err := os.ReadDir(clientsDir); err == nil {
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".crt") {
						certPath := filepath.Join(clientsDir, entry.Name())
						cert, err := pki.LoadCertificateOnly(certPath)
						if err != nil {
							continue
						}

						expired := cert.IsExpired()
						expiringSoon := cert.IsExpiringSoon(warningDays)
						daysUntil := cert.DaysUntilExpiry()
						name := strings.TrimSuffix(entry.Name(), ".crt")

						if expired {
							fmt.Printf("❌ EXPIRED: Client/%s (expired %d days ago)\n", name, -daysUntil)
							expiredCount++
						} else if expiringSoon {
							fmt.Printf("⚠️  EXPIRING SOON: Client/%s (expires in %d days)\n", name, daysUntil)
							expiringSoonCount++
						} else {
							okCount++
						}
					}
				}
			}

			fmt.Printf("\nSummary:\n")
			fmt.Printf("  ✓ OK:            %d\n", okCount)
			fmt.Printf("  ⚠️  Expiring Soon: %d\n", expiringSoonCount)
			fmt.Printf("  ❌ Expired:       %d\n", expiredCount)
			fmt.Printf("\n")

			if expiredCount > 0 {
				return fmt.Errorf("found %d expired certificate(s)", expiredCount)
			}

			if expiringSoonCount > 0 {
				fmt.Printf("⚠️  Warning: %d certificate(s) expiring soon. Consider renewal.\n", expiringSoonCount)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "./certs", "Directory containing certificates")
	cmd.Flags().IntVar(&warningDays, "warning-days", 30, "Warn if certificate expires within this many days")

	return cmd
}
