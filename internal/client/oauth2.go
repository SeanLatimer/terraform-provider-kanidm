package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

// OAuth2Client represents a Kanidm OAuth2 resource server
type OAuth2Client struct {
	UUID                        string
	Name                        string
	DisplayName                 string
	Origin                      string
	RedirectURIs                []string
	ScopeMaps                   []OAuth2ScopeMap
	SupScopeMaps                []OAuth2ScopeMap
	ClaimMaps                   []OAuth2ClaimMap
	ClientID                    string // Computed
	ClientSecret                string // Only for basic/confidential clients, populated on creation
	IsPublic                    bool
	PreferShortUsername         bool
	PreferShortUsernameSet      bool
	AllowInsecureDisablePKCE    bool
	AllowInsecureDisablePKCESet bool
	JWTLegacyCryptoEnable       bool
	JWTLegacyCryptoEnableSet    bool
}

// OAuth2ScopeMap represents a scope mapping for an OAuth2 client
type OAuth2ScopeMap struct {
	Group  string
	Scopes []string
}

// OAuth2ClaimMap represents a claim mapping for an OAuth2 client
type OAuth2ClaimMap struct {
	Name   string
	Group  string
	Values []string
	Join   string
}

// ParseOAuth2ScopeMap parses a scope map proto string from the REST API.
// Expected formats:
//   - "group-spn@domain: {\"scope1\", \"scope2\"}"
//   - "group-uuid: {\"scope1\", \"scope2\"}"
func ParseOAuth2ScopeMap(raw string) (group string, scopes []string, err error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid scope map format: %q", raw)
	}

	group = strings.TrimSpace(parts[0])
	scopesPart := strings.TrimSpace(parts[1])

	// Remove surrounding braces
	scopesPart = strings.TrimPrefix(scopesPart, "{")
	scopesPart = strings.TrimSuffix(scopesPart, "}")

	// Split by comma and trim quotes/spaces
	for _, s := range strings.Split(scopesPart, ",") {
		s = strings.TrimSpace(s)
		s = strings.Trim(s, "\"")
		if s != "" {
			scopes = append(scopes, s)
		}
	}

	return group, scopes, nil
}

// ParseOAuth2ClaimMap parses a claim map proto string from the REST API.
// Expected format: "claim_name:group-spn@domain:join_char:\"joined_values\""
// join_char is the actual separator: "," for csv, " " for ssv, ";" for array
func ParseOAuth2ClaimMap(raw string) (claimName, group, joinStrategy string, values []string, err error) {
	parts := strings.SplitN(raw, ":", 4)
	if len(parts) != 4 {
		return "", "", "", nil, fmt.Errorf("invalid claim map format: %q", raw)
	}

	claimName = parts[0]
	group = parts[1]
	joinChar := parts[2]
	valuesPart := strings.Trim(parts[3], "\"")

	// Map join char to strategy name
	switch joinChar {
	case ",":
		joinStrategy = "csv"
	case " ":
		joinStrategy = "ssv"
	case ";":
		joinStrategy = "array"
	default:
		joinStrategy = "array"
	}

	// The REST API always stores claim values as comma-separated inside the quotes,
	// regardless of the join strategy. Split by comma to get individual values.
	if valuesPart != "" {
		for _, v := range strings.Split(valuesPart, ",") {
			if v != "" {
				values = append(values, v)
			}
		}
	}

	return claimName, group, joinStrategy, values, nil
}

// ListOAuth2Clients lists all OAuth2 clients visible to the caller.
func (c *Client) ListOAuth2Clients(ctx context.Context) ([]OAuth2Client, error) {
	resp, err := c.doRequest(ctx, "GET", "/v1/oauth2", nil)
	if err != nil {
		return nil, fmt.Errorf("list oauth2 clients: %w", err)
	}

	var entries []Entry
	if err := decodeResponse(resp, &entries); err != nil {
		return nil, err
	}

	clients := make([]OAuth2Client, 0, len(entries))
	for _, entry := range entries {
		_, hasBasicSecret := entry.Attrs["oauth2_rs_basic_secret"]
		isPublic := !hasBasicSecret

		clientName := entry.GetString("name")
		if clientName == "" {
			clientName = entry.GetString("oauth2_rs_name")
		}

		origin := entry.GetString("oauth2_rs_origin_landing")
		if len(origin) > 0 && origin[len(origin)-1] == '/' {
			origin = origin[:len(origin)-1]
		}

		scopeMaps, err := parseScopeMapEntries(entry.GetStringSlice("oauth2_rs_scope_map"))
		if err != nil {
			return nil, fmt.Errorf("parse oauth2 scope maps for %q: %w", clientName, err)
		}
		supScopeMaps, err := parseScopeMapEntries(entry.GetStringSlice("oauth2_rs_sup_scope_map"))
		if err != nil {
			return nil, fmt.Errorf("parse oauth2 supplemental scope maps for %q: %w", clientName, err)
		}
		claimMaps, err := parseClaimMapEntries(entry.GetStringSlice("oauth2_rs_claim_map"))
		if err != nil {
			return nil, fmt.Errorf("parse oauth2 claim maps for %q: %w", clientName, err)
		}

		preferShort, preferShortSet := entry.GetBool("oauth2_prefer_short_username")
		disablePKCE, disablePKCESet := entry.GetBool("oauth2_allow_insecure_client_disable_pkce")
		jwtLegacy, jwtLegacySet := entry.GetBool("oauth2_jwt_legacy_crypto_enable")

		clients = append(clients, OAuth2Client{
			UUID:                        firstNonEmpty(entry.GetString("entryuuid"), entry.GetString("uuid")),
			Name:                        clientName,
			DisplayName:                 entry.GetString("displayname"),
			Origin:                      origin,
			RedirectURIs:                entry.GetStringSlice("oauth2_rs_origin"),
			ScopeMaps:                   scopeMaps,
			SupScopeMaps:                supScopeMaps,
			ClaimMaps:                   claimMaps,
			ClientID:                    clientName,
			IsPublic:                    isPublic,
			PreferShortUsername:         preferShort,
			PreferShortUsernameSet:      preferShortSet,
			AllowInsecureDisablePKCE:    disablePKCE,
			AllowInsecureDisablePKCESet: disablePKCESet,
			JWTLegacyCryptoEnable:       jwtLegacy,
			JWTLegacyCryptoEnableSet:    jwtLegacySet,
		})
	}

	return clients, nil
}

func parseScopeMapEntries(rawEntries []string) ([]OAuth2ScopeMap, error) {
	if len(rawEntries) == 0 {
		return nil, nil
	}

	var maps []OAuth2ScopeMap
	for _, raw := range rawEntries {
		group, scopes, err := ParseOAuth2ScopeMap(raw)
		if err != nil {
			return nil, err
		}
		maps = append(maps, OAuth2ScopeMap{Group: group, Scopes: scopes})
	}
	return maps, nil
}

func parseClaimMapEntries(rawEntries []string) ([]OAuth2ClaimMap, error) {
	if len(rawEntries) == 0 {
		return nil, nil
	}

	var maps []OAuth2ClaimMap
	for _, raw := range rawEntries {
		claimName, group, join, values, err := ParseOAuth2ClaimMap(raw)
		if err != nil {
			return nil, err
		}
		maps = append(maps, OAuth2ClaimMap{Name: claimName, Group: group, Values: values, Join: join})
	}
	return maps, nil
}

// ResolveOAuth2Client resolves an OAuth2 client by current name or stable UUID.
func (c *Client) ResolveOAuth2Client(ctx context.Context, identifier string) (*OAuth2Client, error) {
	clients, err := c.ListOAuth2Clients(ctx)
	if err != nil {
		return nil, err
	}

	for _, oauth2Client := range clients {
		if oauth2Client.UUID == identifier || oauth2Client.Name == identifier {
			clientCopy := oauth2Client
			return &clientCopy, nil
		}
	}

	return nil, ErrNotFound
}

// CreateOAuth2BasicClient creates a new OAuth2 basic (confidential) client
func (c *Client) CreateOAuth2BasicClient(ctx context.Context, name, displayName, origin string) (*OAuth2Client, error) {
	req := NewCreateRequest(map[string]any{
		"name":                     []string{name},
		"displayname":              []string{displayName},
		"oauth2_rs_origin_landing": []string{origin},
	})

	resp, err := c.doRequest(ctx, "POST", "/v1/oauth2/_basic", req)
	if err != nil {
		return nil, fmt.Errorf("create oauth2 basic client: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The create response doesn't include the client secret
	// We need to retrieve it using the show secret endpoint
	clientSecret, err := c.GetOAuth2BasicSecret(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("retrieve client secret: %w", err)
	}

	return &OAuth2Client{
		Name:         name,
		DisplayName:  displayName,
		Origin:       origin,
		ClientID:     name, // Client ID is typically the name
		ClientSecret: clientSecret,
		IsPublic:     false,
	}, nil
}

// CreateOAuth2PublicClient creates a new OAuth2 public client
func (c *Client) CreateOAuth2PublicClient(ctx context.Context, name, displayName, origin string) (*OAuth2Client, error) {
	req := NewCreateRequest(map[string]any{
		"name":                     []string{name},
		"displayname":              []string{displayName},
		"oauth2_rs_origin_landing": []string{origin},
	})

	resp, err := c.doRequest(ctx, "POST", "/v1/oauth2/_public", req)
	if err != nil {
		return nil, fmt.Errorf("create oauth2 public client: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return &OAuth2Client{
		Name:        name,
		DisplayName: displayName,
		Origin:      origin,
		ClientID:    name,
		IsPublic:    true,
	}, nil
}

// GetOAuth2Client retrieves an OAuth2 client by name
func (c *Client) GetOAuth2Client(ctx context.Context, name string) (*OAuth2Client, error) {
	resp, err := c.doRequest(ctx, "GET", "/v1/oauth2/"+name, nil)
	if err != nil {
		return nil, fmt.Errorf("get oauth2 client: %w", err)
	}

	var entry Entry
	if err := decodeResponse(resp, &entry); err != nil {
		return nil, err
	}

	// Determine if public based on oauth2_rs_basic_secret attribute presence
	// Note: The value is hidden for basic clients, so we check if the key exists in attrs
	_, hasBasicSecret := entry.Attrs["oauth2_rs_basic_secret"]
	isPublic := !hasBasicSecret

	// Use 'name' attribute for the name (not oauth2_rs_name which is for internal use)
	clientName := entry.GetString("name")
	if clientName == "" {
		clientName = entry.GetString("oauth2_rs_name")
	}

	// Get origin and normalize by removing trailing slash if present
	// (Kanidm adds trailing slash, but Terraform configs typically don't have it)
	origin := entry.GetString("oauth2_rs_origin_landing")
	if len(origin) > 0 && origin[len(origin)-1] == '/' {
		origin = origin[:len(origin)-1]
	}
	preferShort, preferShortSet := entry.GetBool("oauth2_prefer_short_username")
	disablePKCE, disablePKCESet := entry.GetBool("oauth2_allow_insecure_client_disable_pkce")
	jwtLegacy, jwtLegacySet := entry.GetBool("oauth2_jwt_legacy_crypto_enable")

	scopeMaps, err := parseScopeMapEntries(entry.GetStringSlice("oauth2_rs_scope_map"))
	if err != nil {
		return nil, fmt.Errorf("parse oauth2 scope maps for %q: %w", clientName, err)
	}
	supScopeMaps, err := parseScopeMapEntries(entry.GetStringSlice("oauth2_rs_sup_scope_map"))
	if err != nil {
		return nil, fmt.Errorf("parse oauth2 supplemental scope maps for %q: %w", clientName, err)
	}
	claimMaps, err := parseClaimMapEntries(entry.GetStringSlice("oauth2_rs_claim_map"))
	if err != nil {
		return nil, fmt.Errorf("parse oauth2 claim maps for %q: %w", clientName, err)
	}

	return &OAuth2Client{
		UUID:                        firstNonEmpty(entry.GetString("entryuuid"), entry.GetString("uuid")),
		Name:                        clientName,
		DisplayName:                 entry.GetString("displayname"),
		Origin:                      origin,
		RedirectURIs:                entry.GetStringSlice("oauth2_rs_origin"),
		ScopeMaps:                   scopeMaps,
		SupScopeMaps:                supScopeMaps,
		ClaimMaps:                   claimMaps,
		ClientID:                    clientName,
		IsPublic:                    isPublic,
		PreferShortUsername:         preferShort,
		PreferShortUsernameSet:      preferShortSet,
		AllowInsecureDisablePKCE:    disablePKCE,
		AllowInsecureDisablePKCESet: disablePKCESet,
		JWTLegacyCryptoEnable:       jwtLegacy,
		JWTLegacyCryptoEnableSet:    jwtLegacySet,
		// Note: Client secret is never returned in GET responses
	}, nil
}

type UpdateOAuth2ClientOpts struct {
	NewName                  *string
	DisplayName              string
	Origin                   string
	RedirectURIs             []string
	PreferShortUsername      *bool
	AllowInsecureDisablePKCE *bool
	JWTLegacyCryptoEnable    *bool
}

// UpdateOAuth2Client updates an OAuth2 client. If NewName is non-nil, the client is renamed.
func (c *Client) UpdateOAuth2Client(ctx context.Context, name string, opts UpdateOAuth2ClientOpts) error {
	attrs := make(map[string]any)

	if opts.NewName != nil {
		attrs["name"] = []string{*opts.NewName}
	}

	if opts.DisplayName != "" {
		attrs["displayname"] = []string{opts.DisplayName}
	}

	if opts.Origin != "" {
		attrs["oauth2_rs_origin_landing"] = []string{opts.Origin}
	}

	if opts.RedirectURIs != nil {
		attrs["oauth2_rs_origin"] = opts.RedirectURIs
	}

	if opts.PreferShortUsername != nil {
		value := "false"
		if *opts.PreferShortUsername {
			value = "true"
		}
		attrs["oauth2_prefer_short_username"] = []string{value}
	}

	if opts.AllowInsecureDisablePKCE != nil {
		if *opts.AllowInsecureDisablePKCE {
			attrs["oauth2_allow_insecure_client_disable_pkce"] = []string{"true"}
		} else {
			attrs["oauth2_allow_insecure_client_disable_pkce"] = []string{}
		}
	}

	if opts.JWTLegacyCryptoEnable != nil {
		value := "false"
		if *opts.JWTLegacyCryptoEnable {
			value = "true"
		}
		attrs["oauth2_jwt_legacy_crypto_enable"] = []string{value}
	}

	req := NewUpdateRequest(attrs)

	resp, err := c.doRequest(ctx, "PATCH", "/v1/oauth2/"+name, req)
	if err != nil {
		return fmt.Errorf("update oauth2 client: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// DeleteOAuth2Client deletes an OAuth2 client
func (c *Client) DeleteOAuth2Client(ctx context.Context, name string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/v1/oauth2/"+name, nil)
	if err != nil {
		return fmt.Errorf("delete oauth2 client: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// SetOAuth2ScopeMap sets the scope mapping for an OAuth2 client
func (c *Client) SetOAuth2ScopeMap(ctx context.Context, rsName, groupName string, scopes []string) error {
	// Send scopes array directly (not wrapped in an object)
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/oauth2/%s/_scopemap/%s", rsName, groupName), scopes)
	if err != nil {
		return fmt.Errorf("set oauth2 scope map: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// DeleteOAuth2ScopeMap removes a scope mapping for an OAuth2 client
func (c *Client) DeleteOAuth2ScopeMap(ctx context.Context, rsName, groupName string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/v1/oauth2/%s/_scopemap/%s", rsName, groupName), nil)
	if err != nil {
		return fmt.Errorf("delete oauth2 scope map: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// SetOAuth2SupScopeMap sets the supplemental scope mapping for an OAuth2 client
func (c *Client) SetOAuth2SupScopeMap(ctx context.Context, rsName, groupName string, scopes []string) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/oauth2/%s/_sup_scopemap/%s", rsName, groupName), scopes)
	if err != nil {
		return fmt.Errorf("set oauth2 sup scope map: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// DeleteOAuth2SupScopeMap removes a supplemental scope mapping for an OAuth2 client
func (c *Client) DeleteOAuth2SupScopeMap(ctx context.Context, rsName, groupName string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/v1/oauth2/%s/_sup_scopemap/%s", rsName, groupName), nil)
	if err != nil {
		return fmt.Errorf("delete oauth2 sup scope map: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// SetOAuth2ClaimMap sets the claim mapping for an OAuth2 client
func (c *Client) SetOAuth2ClaimMap(ctx context.Context, rsName, claimName, groupName string, values []string) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/oauth2/%s/_claimmap/%s/%s", rsName, claimName, groupName), values)
	if err != nil {
		return fmt.Errorf("set oauth2 claim map: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// SetOAuth2ClaimMapJoin sets the join strategy for a claim map on an OAuth2 client
func (c *Client) SetOAuth2ClaimMapJoin(ctx context.Context, rsName, claimName, join string) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/oauth2/%s/_claimmap/%s", rsName, claimName), join)
	if err != nil {
		return fmt.Errorf("set oauth2 claim map join: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// DeleteOAuth2ClaimMap removes a claim mapping for an OAuth2 client
func (c *Client) DeleteOAuth2ClaimMap(ctx context.Context, rsName, claimName, groupName string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/v1/oauth2/%s/_claimmap/%s/%s", rsName, claimName, groupName), nil)
	if err != nil {
		return fmt.Errorf("delete oauth2 claim map: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// GetOAuth2BasicSecret retrieves the client secret for a basic OAuth2 client
func (c *Client) GetOAuth2BasicSecret(ctx context.Context, name string) (string, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/v1/oauth2/%s/_basic_secret", name), nil)
	if err != nil {
		return "", fmt.Errorf("get oauth2 basic secret: %w", err)
	}

	// The API returns the secret as a plain JSON string
	var secret string
	if err := decodeResponse(resp, &secret); err != nil {
		return "", err
	}

	return secret, nil
}

// RegenerateOAuth2BasicSecret regenerates the client secret for a basic OAuth2 client
// This invalidates the old secret and generates a new one
func (c *Client) RegenerateOAuth2BasicSecret(ctx context.Context, name string) (string, error) {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/oauth2/%s/_basic_secret", name), nil)
	if err != nil {
		return "", fmt.Errorf("regenerate oauth2 basic secret: %w", err)
	}

	// The API returns the new secret as a plain JSON string
	var secret string
	if err := decodeResponse(resp, &secret); err != nil {
		return "", err
	}

	return secret, nil
}

// UploadOAuth2Image uploads or replaces an OAuth2 client image.
func (c *Client) UploadOAuth2Image(ctx context.Context, name, imagePath string) error {
	fileContents, err := os.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("read oauth2 image: %w", err)
	}

	contentType := mime.TypeByExtension(filepath.Ext(imagePath))
	if contentType == "" {
		return fmt.Errorf("determine oauth2 image content type for %q", imagePath)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="image"; filename="%s"`, filepath.Base(imagePath)))
	header.Set("Content-Type", contentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return fmt.Errorf("create oauth2 image multipart part: %w", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(fileContents)); err != nil {
		return fmt.Errorf("write oauth2 image multipart body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close oauth2 image multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+fmt.Sprintf("/v1/oauth2/%s/_image", name), &body)
	if err != nil {
		return fmt.Errorf("create oauth2 image request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute oauth2 image request: %w", err)
	}

	if err := c.checkResponse(resp); err != nil {
		return fmt.Errorf("upload oauth2 image: %w", err)
	}

	_ = resp.Body.Close()
	return nil
}

// DeleteOAuth2Image removes the image associated with an OAuth2 client.
func (c *Client) DeleteOAuth2Image(ctx context.Context, name string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/v1/oauth2/%s/_image", name), nil)
	if err != nil {
		return fmt.Errorf("delete oauth2 image: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}
