package client

import (
	"context"
	"fmt"
)

const (
	personAttrLegalName = "legalname"
	personAttrValidFrom = "account_valid_from"
	personAttrExpireAt  = "account_expire"
)

// Person represents a Kanidm person account
type Person struct {
	UUID        string
	Name        string
	SPN         string
	DisplayName string
	LegalName   string
	GIDNumber   *int64
	Shell       string
	ValidFrom   string
	ExpireAt    string
	Mail        []string
}

// CreatePerson creates a new person account
func (c *Client) CreatePerson(ctx context.Context, name, displayName string) (*Person, error) {
	req := NewCreateRequest(map[string]any{
		"name":        []string{name},
		"displayname": []string{displayName},
	})

	resp, err := c.doRequest(ctx, "POST", "/v1/person", req)
	if err != nil {
		return nil, fmt.Errorf("create person: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Return the created person
	return &Person{
		Name:        name,
		DisplayName: displayName,
	}, nil
}

// GetPerson retrieves a person account by ID
func (c *Client) GetPerson(ctx context.Context, id string) (*Person, error) {
	resp, err := c.doRequest(ctx, "GET", "/v1/person/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("get person: %w", err)
	}

	var entry Entry
	if err := decodeResponse(resp, &entry); err != nil {
		return nil, err
	}

	return &Person{
		UUID:        firstNonEmpty(entry.GetString("entryuuid"), entry.GetString("uuid")),
		Name:        entry.GetString("name"),
		SPN:         entry.GetString("spn"),
		DisplayName: entry.GetString("displayname"),
		LegalName:   entry.GetString("legalname"),
		ValidFrom:   entry.GetString(personAttrValidFrom),
		ExpireAt:    entry.GetString(personAttrExpireAt),
		Mail:        entry.GetStringSlice("mail"),
	}, nil
}

// UpdatePerson updates a person account
func (c *Client) UpdatePerson(ctx context.Context, id string, name *string, displayName *string, mail []string) error {
	attrs := make(map[string]any)

	if name != nil {
		attrs["name"] = []string{*name}
	}

	if displayName != nil {
		attrs["displayname"] = []string{*displayName}
	}

	if mail != nil {
		attrs["mail"] = mail
	}

	req := NewUpdateRequest(attrs)

	resp, err := c.doRequest(ctx, "PATCH", "/v1/person/"+id, req)
	if err != nil {
		return fmt.Errorf("update person: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// SetPersonLegalName sets the legal name for a person account.
func (c *Client) SetPersonLegalName(ctx context.Context, id, legalName string) error {
	resp, err := c.doRequest(ctx, "PUT", "/v1/person/"+id+"/_attr/"+personAttrLegalName, []string{legalName})
	if err != nil {
		return fmt.Errorf("set person legal name: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// ClearPersonLegalName clears the legal name for a person account.
func (c *Client) ClearPersonLegalName(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/v1/person/"+id+"/_attr/"+personAttrLegalName, nil)
	if err != nil {
		return fmt.Errorf("clear person legal name: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func (c *Client) SetPersonValidFrom(ctx context.Context, id, validFrom string) error {
	resp, err := c.doRequest(ctx, "PUT", "/v1/person/"+id+"/_attr/"+personAttrValidFrom, []string{validFrom})
	if err != nil {
		return fmt.Errorf("set person valid_from: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func (c *Client) ClearPersonValidFrom(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/v1/person/"+id+"/_attr/"+personAttrValidFrom, nil)
	if err != nil {
		return fmt.Errorf("clear person valid_from: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func (c *Client) SetPersonExpireAt(ctx context.Context, id, expireAt string) error {
	resp, err := c.doRequest(ctx, "PUT", "/v1/person/"+id+"/_attr/"+personAttrExpireAt, []string{expireAt})
	if err != nil {
		return fmt.Errorf("set person expire_at: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func (c *Client) ClearPersonExpireAt(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/v1/person/"+id+"/_attr/"+personAttrExpireAt, nil)
	if err != nil {
		return fmt.Errorf("clear person expire_at: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func (c *Client) SetPersonUnix(ctx context.Context, id string, gidNumber *int64, shell *string) error {
	body := map[string]any{}
	if gidNumber != nil {
		body["gidnumber"] = *gidNumber
	}
	if shell != nil {
		body["shell"] = *shell
	}
	resp, err := c.doRequest(ctx, "POST", "/v1/person/"+id+"/_unix", body)
	if err != nil {
		return fmt.Errorf("set person unix: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

// DeletePerson deletes a person account
func (c *Client) DeletePerson(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/v1/person/"+id, nil)
	if err != nil {
		return fmt.Errorf("delete person: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// SetPersonPassword sets the password for a person account
func (c *Client) SetPersonPassword(ctx context.Context, id, password string) error {
	// Note: This uses the credential update intent API
	// Implementation will depend on Kanidm's exact credential management flow
	req := map[string]any{
		"password": password,
	}

	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/person/%s/_credential/_update_intent", id), req)
	if err != nil {
		return fmt.Errorf("set person password: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// CreatePersonCredentialResetToken creates a credential reset token for passkey/password setup via UI
// This enables the modern Kanidm workflow: create person -> generate token -> user sets up credentials
// The ttl parameter is optional and specifies the token lifetime in seconds
func (c *Client) CreatePersonCredentialResetToken(ctx context.Context, id string, ttl *int) (string, error) {
	path := fmt.Sprintf("/v1/person/%s/_credential/_update_intent", id)
	if ttl != nil {
		path = fmt.Sprintf("/v1/person/%s/_credential/_update_intent/%d", id, *ttl)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return "", fmt.Errorf("create credential reset token: %w", err)
	}

	var result struct {
		Token string `json:"token"`
	}

	if err := decodeResponse(resp, &result); err != nil {
		return "", err
	}

	return result.Token, nil
}
