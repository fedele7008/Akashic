package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"

	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
)

// Client represents an LDAP client for user authentication and management
type Client struct {
	conn   *ldap.Conn
	config *config.LDAPConfig
	logger *logging.Logger
}

// UserInfo represents user information retrieved from LDAP
type UserInfo struct {
	DN          string // Distinguished Name
	Username    string
	Email       string
	DisplayName string
}

// New creates a new LDAP client
func New(cfg *config.LDAPConfig, logger *logging.Logger) *Client {
	return &Client{
		config: cfg,
		logger: logger,
	}
}

// Connect establishes a connection to the LDAP server and performs bind
func (c *Client) Connect() error {
	var err error

	// Build LDAP URL based on TLS configuration
	var ldapURL string
	if c.config.UseTLS {
		ldapURL = fmt.Sprintf("ldaps://%s:%d", c.config.Host, c.config.Port)
	} else {
		ldapURL = fmt.Sprintf("ldap://%s:%d", c.config.Host, c.config.Port)
	}

	c.logger.App.Info("connecting to LDAP server",
		zap.String("url", ldapURL),
		zap.Bool("tls", c.config.UseTLS),
	)

	// Configure TLS if enabled
	var tlsConfig *tls.Config
	if c.config.UseTLS {
		tlsConfig = &tls.Config{
			ServerName:         c.config.Host,
			InsecureSkipVerify: c.config.TLSSkipVerify,
		}
	}

	// Connect to LDAP server using DialURL (recommended method)
	c.conn, err = ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %v", err)
	}

	// Set connection timeout
	c.conn.SetTimeout(10 * time.Second)

	// Bind as admin user
	if err := c.conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to bind as admin: %v", err)
	}

	c.logger.App.Info("successfully connected to LDAP server",
		zap.String("bind_dn", c.config.BindDN),
	)

	return nil
}

// Close closes the LDAP connection
func (c *Client) Close() error {
	if c.conn != nil {
		c.logger.App.Info("closing LDAP connection")
		c.conn.Close()
		c.conn = nil
	}
	return nil
}

// TestConnection verifies that the LDAP connection is working
func (c *Client) TestConnection() error {
	if c.conn == nil {
		return fmt.Errorf("LDAP connection not established")
	}

	// Try a simple search to verify connection
	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, // size limit (0 = no limit)
		0, // time limit (0 = no limit)
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err := c.conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("LDAP connection test failed: %v", err)
	}

	return nil
}

// InitializeStructure creates the required LDAP organizational structure
// This is similar to GORM's AutoMigrate - it ensures the LDAP directory structure exists
// This method is idempotent - safe to call multiple times
func (c *Client) InitializeStructure() error {
	if c.conn == nil {
		return fmt.Errorf("LDAP connection not established")
	}

	c.logger.App.Info("initializing LDAP directory structure")

	// Define organizational units to create
	orgUnits := []struct {
		DN          string
		OU          string
		Description string
	}{
		{
			DN:          c.config.UserSearchBase, // ou=users,dc=akashic,dc=local
			OU:          "users",
			Description: "Akashic Users",
		},
		{
			DN:          fmt.Sprintf("ou=groups,%s", c.config.BaseDN),
			OU:          "groups",
			Description: "Akashic Groups",
		},
	}

	// Create each organizational unit if it doesn't exist
	for _, ou := range orgUnits {
		if err := c.createOrgUnitIfNotExists(ou.DN, ou.OU, ou.Description); err != nil {
			return fmt.Errorf("failed to initialize LDAP structure: %v", err)
		}
	}

	// Define RBAC groups to create
	rbacGroups := []struct {
		CN          string
		Description string
	}{
		{
			CN:          "akashic-root",
			Description: "Akashic Root Users - Highest permission level",
		},
		{
			CN:          "akashic-admins",
			Description: "Akashic Administrators - Full administrative access",
		},
		{
			CN:          "akashic-users",
			Description: "Akashic Regular Users - Standard user permissions",
		},
	}

	// Create each RBAC group if it doesn't exist
	for _, group := range rbacGroups {
		if err := c.createGroupIfNotExists(group.CN, group.Description); err != nil {
			return fmt.Errorf("failed to initialize RBAC groups: %v", err)
		}
	}

	c.logger.App.Info("LDAP directory structure initialized successfully")
	return nil
}

// createOrgUnitIfNotExists creates an organizational unit if it doesn't already exist
func (c *Client) createOrgUnitIfNotExists(dn, ou, description string) error {
	// Check if the organizational unit already exists
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=organizationalUnit)",
		[]string{"dn"},
		nil,
	)

	_, err := c.conn.Search(searchRequest)
	if err == nil {
		// OU already exists
		c.logger.App.Debug("organizational unit already exists",
			zap.String("dn", dn))
		return nil
	}

	// Check if it's a "no such object" error (OU doesn't exist)
	if !strings.Contains(err.Error(), "No Such Object") {
		// Some other error occurred
		return fmt.Errorf("failed to check if OU exists: %v", err)
	}

	// OU doesn't exist, create it
	c.logger.App.Info("creating organizational unit",
		zap.String("dn", dn),
		zap.String("ou", ou))

	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"organizationalUnit"})
	addReq.Attribute("ou", []string{ou})
	if description != "" {
		addReq.Attribute("description", []string{description})
	}

	if err := c.conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create organizational unit %s: %v", dn, err)
	}

	c.logger.App.Info("organizational unit created successfully",
		zap.String("dn", dn))

	return nil
}

// createGroupIfNotExists creates an LDAP group if it doesn't already exist
func (c *Client) createGroupIfNotExists(cn, description string) error {
	groupDN := fmt.Sprintf("cn=%s,ou=groups,%s", cn, c.config.BaseDN)

	// Check if the group already exists
	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=groupOfNames)",
		[]string{"dn"},
		nil,
	)

	_, err := c.conn.Search(searchRequest)
	if err == nil {
		// Group already exists
		c.logger.App.Debug("RBAC group already exists",
			zap.String("dn", groupDN),
			zap.String("cn", cn))
		return nil
	}

	// Check if it's a "no such object" error (group doesn't exist)
	if !strings.Contains(err.Error(), "No Such Object") {
		// Some other error occurred
		return fmt.Errorf("failed to check if group exists: %v", err)
	}

	// Group doesn't exist, create it
	c.logger.App.Info("creating RBAC group",
		zap.String("dn", groupDN),
		zap.String("cn", cn))

	addReq := ldap.NewAddRequest(groupDN, nil)
	addReq.Attribute("objectClass", []string{"groupOfNames", "top"})
	addReq.Attribute("cn", []string{cn})
	if description != "" {
		addReq.Attribute("description", []string{description})
	}
	// groupOfNames requires at least one member - use placeholder
	addReq.Attribute("member", []string{fmt.Sprintf("cn=placeholder,ou=groups,%s", c.config.BaseDN)})

	if err := c.conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create RBAC group %s: %v", groupDN, err)
	}

	c.logger.Security.Info("RBAC group created successfully",
		zap.String("dn", groupDN),
		zap.String("cn", cn))

	return nil
}

// Authenticate verifies user credentials against LDAP
// Returns the user's DN if authentication succeeds
func (c *Client) Authenticate(username, password string) (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("LDAP connection not established")
	}

	// Search for the user
	userDN, err := c.searchUserDN(username)
	if err != nil {
		c.logger.Security.Warn("failed to find user for authentication",
			zap.String("username", username),
			zap.Error(err),
		)
		return "", fmt.Errorf("user not found: %v", err)
	}

	// Try to bind as the user (this performs authentication)
	if err := c.conn.Bind(userDN, password); err != nil {
		c.logger.Security.Warn("authentication failed for user",
			zap.String("username", username),
			zap.String("dn", userDN),
		)
		return "", fmt.Errorf("invalid credentials")
	}

	c.logger.Security.Info("user authenticated successfully",
		zap.String("username", username),
		zap.String("dn", userDN),
	)

	// Rebind as admin for subsequent operations
	if err := c.conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return "", fmt.Errorf("failed to rebind as admin: %v", err)
	}

	return userDN, nil
}

// GetUser retrieves user information by username
func (c *Client) GetUser(username string) (*UserInfo, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	// Build search filter
	filter := strings.ReplaceAll(c.config.UserSearchFilter, "{username}", ldap.EscapeFilter(username))

	// Define attributes to retrieve
	attributes := []string{
		c.config.UsernameAttr,
		c.config.EmailAttr,
		c.config.DisplayNameAttr,
	}

	// Create search request
	searchRequest := ldap.NewSearchRequest(
		c.config.UserSearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // size limit - we expect exactly one result
		0, // time limit (0 = no limit)
		false,
		filter,
		attributes,
		nil,
	)

	// Execute search
	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found in LDAP")
	}

	if len(sr.Entries) > 1 {
		c.logger.Security.Warn("multiple LDAP entries found for username",
			zap.String("username", username),
			zap.Int("count", len(sr.Entries)),
		)
	}

	entry := sr.Entries[0]
	userInfo := &UserInfo{
		DN:          entry.DN,
		Username:    entry.GetAttributeValue(c.config.UsernameAttr),
		Email:       entry.GetAttributeValue(c.config.EmailAttr),
		DisplayName: entry.GetAttributeValue(c.config.DisplayNameAttr),
	}

	return userInfo, nil
}

// GetUserByDN retrieves user information by Distinguished Name
func (c *Client) GetUserByDN(dn string) (*UserInfo, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	// Define attributes to retrieve
	attributes := []string{
		c.config.UsernameAttr,
		c.config.EmailAttr,
		c.config.DisplayNameAttr,
	}

	// Create search request for specific DN
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, // size limit
		0, // time limit (0 = no limit)
		false,
		"(objectClass=*)",
		attributes,
		nil,
	)

	// Execute search
	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search by DN failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user DN not found in LDAP")
	}

	entry := sr.Entries[0]
	userInfo := &UserInfo{
		DN:          entry.DN,
		Username:    entry.GetAttributeValue(c.config.UsernameAttr),
		Email:       entry.GetAttributeValue(c.config.EmailAttr),
		DisplayName: entry.GetAttributeValue(c.config.DisplayNameAttr),
	}

	return userInfo, nil
}

// UserExists checks if a user exists in LDAP by username
func (c *Client) UserExists(username string) (bool, error) {
	_, err := c.searchUserDN(username)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// searchUserDN searches for a user and returns their DN
func (c *Client) searchUserDN(username string) (string, error) {
	filter := strings.ReplaceAll(c.config.UserSearchFilter, "{username}", ldap.EscapeFilter(username))

	searchRequest := ldap.NewSearchRequest(
		c.config.UserSearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // size limit
		0, // time limit (0 = no limit)
		false,
		filter,
		[]string{"dn"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user not found")
	}

	return sr.Entries[0].DN, nil
}

// CreateUser creates a new user in LDAP
// This is used during bootstrap to create the root user
func (c *Client) CreateUser(username, email, displayName, password string) (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("LDAP connection not established")
	}

	// Construct the DN for the new user
	userDN := fmt.Sprintf("uid=%s,%s", username, c.config.UserSearchBase)

	c.logger.App.Info("creating new user in LDAP",
		zap.String("username", username),
		zap.String("dn", userDN),
	)

	// Build the add request
	addReq := ldap.NewAddRequest(userDN, nil)

	// Add object classes
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})

	// Add required attributes
	addReq.Attribute("uid", []string{username})
	addReq.Attribute("cn", []string{displayName})
	addReq.Attribute("sn", []string{username}) // surname - required by inetOrgPerson
	addReq.Attribute("mail", []string{email})

	// Add password (LDAP will hash it)
	addReq.Attribute("userPassword", []string{password})

	// Execute the add request
	if err := c.conn.Add(addReq); err != nil {
		c.logger.App.Error("failed to create user in LDAP",
			zap.String("username", username),
			zap.String("dn", userDN),
			zap.Error(err),
		)
		return "", fmt.Errorf("failed to create LDAP user: %w", err)
	}

	c.logger.Security.Info("user created in LDAP",
		zap.String("username", username),
		zap.String("dn", userDN),
	)

	return userDN, nil
}

// ListUsers retrieves all users from LDAP (for deprovisioning reconciliation)
// Returns a map of DN -> UserInfo
func (c *Client) ListUsers() (map[string]*UserInfo, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	// Build filter for all users
	filter := fmt.Sprintf("(objectClass=%s)", c.config.UserObjectClass)

	attributes := []string{
		c.config.UsernameAttr,
		c.config.EmailAttr,
		c.config.DisplayNameAttr,
	}

	searchRequest := ldap.NewSearchRequest(
		c.config.UserSearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // size limit (0 = no limit)
		0, // time limit (0 = no limit)
		false,
		filter,
		attributes,
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %v", err)
	}

	users := make(map[string]*UserInfo, len(sr.Entries))
	for _, entry := range sr.Entries {
		userInfo := &UserInfo{
			DN:          entry.DN,
			Username:    entry.GetAttributeValue(c.config.UsernameAttr),
			Email:       entry.GetAttributeValue(c.config.EmailAttr),
			DisplayName: entry.GetAttributeValue(c.config.DisplayNameAttr),
		}
		users[entry.DN] = userInfo
	}

	c.logger.App.Info("listed LDAP users",
		zap.Int("count", len(users)),
	)

	return users, nil
}

// ============================================================================
// Group Management Methods
// ============================================================================

// CreateGroup creates a new LDAP group with the specified CN and description
// Returns the full DN of the created group
func (c *Client) CreateGroup(cn, description string) (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("LDAP connection not established")
	}

	groupDN := fmt.Sprintf("cn=%s,ou=groups,%s", cn, c.config.BaseDN)

	c.logger.App.Info("creating new group in LDAP",
		zap.String("cn", cn),
		zap.String("dn", groupDN),
	)

	// Create group with groupOfNames object class
	// Note: groupOfNames requires at least one member, so we'll need to add members
	addReq := ldap.NewAddRequest(groupDN, nil)
	addReq.Attribute("objectClass", []string{"groupOfNames", "top"})
	addReq.Attribute("cn", []string{cn})
	if description != "" {
		addReq.Attribute("description", []string{description})
	}
	// groupOfNames requires at least one member - we'll use a placeholder
	// that will be replaced when the first real member is added
	addReq.Attribute("member", []string{fmt.Sprintf("cn=placeholder,ou=groups,%s", c.config.BaseDN)})

	if err := c.conn.Add(addReq); err != nil {
		c.logger.App.Error("failed to create group in LDAP",
			zap.String("cn", cn),
			zap.String("dn", groupDN),
			zap.Error(err),
		)
		return "", fmt.Errorf("failed to create LDAP group: %w", err)
	}

	c.logger.Security.Info("group created in LDAP",
		zap.String("cn", cn),
		zap.String("dn", groupDN),
	)

	return groupDN, nil
}

// GetUserGroups retrieves all groups that the specified user is a member of
// Returns a slice of group DNs
func (c *Client) GetUserGroups(userDN string) ([]string, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	c.logger.App.Debug("fetching groups for user",
		zap.String("user_dn", userDN),
	)

	// Search for groups where the user is a member
	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("ou=groups,%s", c.config.BaseDN), // Search base
		ldap.ScopeWholeSubtree,                       // Scope
		ldap.NeverDerefAliases,                       // Deref
		0,                                            // Size limit (0 = unlimited)
		0,                                            // Time limit (0 = unlimited)
		false,                                        // Types only
		fmt.Sprintf("(member=%s)", userDN),           // Filter
		[]string{"dn", "cn"},                         // Attributes to return
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		c.logger.App.Error("failed to search for user groups",
			zap.String("user_dn", userDN),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to search for user groups: %v", err)
	}

	groups := make([]string, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		groups = append(groups, entry.DN)
	}

	c.logger.App.Debug("found groups for user",
		zap.String("user_dn", userDN),
		zap.Int("group_count", len(groups)),
		zap.Strings("groups", groups),
	)

	return groups, nil
}

// AddUserToGroup adds a user to an LDAP group
func (c *Client) AddUserToGroup(userDN, groupDN string) error {
	if c.conn == nil {
		return fmt.Errorf("LDAP connection not established")
	}

	c.logger.App.Info("adding user to group",
		zap.String("user_dn", userDN),
		zap.String("group_dn", groupDN),
	)

	// Modify the group to add the user as a member
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Add("member", []string{userDN})

	if err := c.conn.Modify(modifyRequest); err != nil {
		// Check if user is already a member (attribute value exists error)
		if strings.Contains(err.Error(), "Attribute or value exists") {
			c.logger.App.Debug("user already member of group",
				zap.String("user_dn", userDN),
				zap.String("group_dn", groupDN),
			)
			return nil // Not an error - user is already a member
		}

		c.logger.App.Error("failed to add user to group",
			zap.String("user_dn", userDN),
			zap.String("group_dn", groupDN),
			zap.Error(err),
		)
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	c.logger.Security.Info("user added to group",
		zap.String("user_dn", userDN),
		zap.String("group_dn", groupDN),
	)

	return nil
}
