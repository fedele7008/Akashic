package main

import (
	"fmt"
	"os"

	"akashic/akashic/pkg/config"
)

func main() {
	fmt.Println("=== Akashic Config Package Demo ===")
	fmt.Println()

	// Test 1: Default configuration (no file)
	fmt.Println("1. Testing default configuration (no config file)...")
	testDefaultConfig()
	fmt.Println()

	// Test 2: Load from simple config file
	fmt.Println("2. Testing configuration loading from file...")
	testConfigFromFile()
	fmt.Println()

	// Test 3: Environment variable overrides
	fmt.Println("3. Testing environment variable overrides...")
	testEnvironmentOverrides()
	fmt.Println()

	// Test 4: Configuration manager with hot reload
	fmt.Println("4. Testing configuration manager...")
	testConfigManager()
	fmt.Println()

	// Test 5: Validation
	fmt.Println("5. Testing configuration validation...")
	testValidation()
	fmt.Println()

	// Test 6: Generate example config
	fmt.Println("6. Testing example config generation...")
	testGenerateExample()
	fmt.Println()

	fmt.Println("=== Demo completed successfully! ===")
}

func testDefaultConfig() {
	loader := config.NewLoader(config.LoaderOptions{
		Environment: "development",
	})

	cfg, err := loader.Load()
	if err != nil {
		fmt.Printf("❌ Error loading default config: %v\n", err)
		return
	}

	authHost := cfg.Server.Auth.Host.GetOrDefault()
	authPort := cfg.Server.Auth.Port.GetOrDefault()
	controlHost := cfg.Server.Control.Host.GetOrDefault()
	controlPort := cfg.Server.Control.Port.GetOrDefault()

	fmt.Printf("✅ Default config loaded successfully\n")
	fmt.Printf("   Auth Server: %s:%d\n", authHost, authPort)
	fmt.Printf("   Control Server: %s:%d\n", controlHost, controlPort)
	fmt.Printf("   Environment: %s\n", cfg.Deployment.Environment.GetOrDefault())
	fmt.Printf("   Debug: %v\n", cfg.Deployment.Debug.GetOrDefault())
}

func testConfigFromFile() {
	// Use the simple config file
	loader := config.NewLoader(config.LoaderOptions{
		ConfigPaths: []string{"./configs/config.yaml"},
		Environment: "development",
		RequireFile: false,
	})

	cfg, err := loader.Load()
	if err != nil {
		fmt.Printf("❌ Error loading config from file: %v\n", err)
		return
	}

	authHost := cfg.Server.Auth.Host.GetOrDefault()
	authPort := cfg.Server.Auth.Port.GetOrDefault()
	controlHost := cfg.Server.Control.Host.GetOrDefault()
	controlPort := cfg.Server.Control.Port.GetOrDefault()
	tlsEnabled := cfg.Server.Control.TLS.Enabled.GetOrDefault()

	fmt.Printf("✅ Config loaded from file successfully\n")
	fmt.Printf("   Auth Server: %s:%d\n", authHost, authPort)
	fmt.Printf("   Control Server: %s:%d (TLS: %v)\n", controlHost, controlPort, tlsEnabled)

	// Test logging config
	serviceName, _ := cfg.Logging.Service.Get()
	env, _ := cfg.Logging.Env.Get()
	fmt.Printf("   Logging: service=%s, env=%s\n", serviceName, env)
}

func testEnvironmentOverrides() {
	// Set some environment variables
	os.Setenv("AKASHIC_SERVER_AUTH_HOST", "192.168.1.100")
	os.Setenv("AKASHIC_SERVER_AUTH_PORT", "9090")
	os.Setenv("AKASHIC_DEPLOYMENT_ENVIRONMENT", "production")
	defer func() {
		os.Unsetenv("AKASHIC_SERVER_AUTH_HOST")
		os.Unsetenv("AKASHIC_SERVER_AUTH_PORT")
		os.Unsetenv("AKASHIC_DEPLOYMENT_ENVIRONMENT")
	}()

	loader := config.NewLoader(config.LoaderOptions{
		Environment:     "development",
		OverrideFromEnv: true,
	})

	cfg, err := loader.Load()
	if err != nil {
		fmt.Printf("❌ Error loading config with env overrides: %v\n", err)
		return
	}

	authHost := cfg.Server.Auth.Host.GetOrDefault()
	authPort := cfg.Server.Auth.Port.GetOrDefault()
	environment := cfg.Deployment.Environment.GetOrDefault()

	fmt.Printf("✅ Environment overrides applied successfully\n")
	fmt.Printf("   Auth Server: %s:%d (overridden by env vars)\n", authHost, authPort)
	fmt.Printf("   Environment: %s (overridden by env var)\n", environment)
}

func testConfigManager() {
	// Test with a non-existent config file (should use defaults)
	manager, err := config.NewManager("./non-existent-config.yaml",
		config.WithEnvironment("development"),
		config.WithHotReload(false), // Disable hot reload for demo
	)
	if err != nil {
		fmt.Printf("❌ Error creating config manager: %v\n", err)
		return
	}
	defer manager.Close()

	cfg := manager.GetConfig()
	authHost := cfg.Server.Auth.Host.GetOrDefault()
	authPort := cfg.Server.Auth.Port.GetOrDefault()

	fmt.Printf("✅ Config manager created successfully\n")
	fmt.Printf("   Auth Server: %s:%d\n", authHost, authPort)

	// Test runtime config updates
	updates := map[string]interface{}{
		"server.auth.port": 9999,
		"server.auth.host": "test.example.com",
	}

	err = manager.UpdateConfig(updates)
	if err != nil {
		fmt.Printf("❌ Error updating config: %v\n", err)
		return
	}

	updatedCfg := manager.GetConfig()
	newAuthHost := updatedCfg.Server.Auth.Host.GetOrDefault()
	newAuthPort := updatedCfg.Server.Auth.Port.GetOrDefault()

	fmt.Printf("✅ Runtime config update successful\n")
	fmt.Printf("   Updated Auth Server: %s:%d\n", newAuthHost, newAuthPort)
}

func testValidation() {
	// Create a config with invalid values
	manager, err := config.NewManager("",
		config.WithEnvironment("development"),
		config.WithHotReload(false),
	)
	if err != nil {
		fmt.Printf("❌ Error creating manager for validation test: %v\n", err)
		return
	}
	defer manager.Close()

	// Test with invalid port (should fail validation)
	updates := map[string]interface{}{
		"server.auth.port": 99999, // Invalid port (too high)
	}

	err = manager.UpdateConfig(updates)
	if err != nil {
		fmt.Printf("✅ Validation working correctly (rejected invalid port)\n")
		fmt.Printf("   Error: %v\n", err)
	} else {
		fmt.Printf("❌ Validation failed - should have rejected invalid port\n")
	}

	// Test explicit validation
	err = manager.ValidateConfiguration()
	if err != nil {
		fmt.Printf("✅ Configuration validation detected issues\n")
		fmt.Printf("   Validation errors: %v\n", err)
	} else {
		fmt.Printf("✅ Current configuration is valid\n")
	}
}

func testGenerateExample() {
	examplePath := "./config.demo.yaml"

	err := config.GenerateExampleConfig(examplePath)
	if err != nil {
		fmt.Printf("❌ Error generating example config: %v\n", err)
		return
	}

	// Check if file was created
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		fmt.Printf("❌ Example config file was not created\n")
		return
	}

	fmt.Printf("✅ Example config generated successfully\n")
	fmt.Printf("   File: %s\n", examplePath)

	// Clean up
	os.Remove(examplePath)
	fmt.Printf("   Cleaned up demo file\n")
}
