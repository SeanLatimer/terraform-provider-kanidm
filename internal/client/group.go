package client

import (
	"context"
	"fmt"
)

// Group represents a Kanidm group
type Group struct {
	UUID        string
	Name        string
	SPN         string
	Description string
	Mail        []string
	GIDNumber   *int64
	EntryManagedBy []string
	Members     []string
}

type UnixGroupToken struct {
	UUID      string `json:"uuid"`
	SPN       string `json:"spn"`
	Name      string `json:"name"`
	GIDNumber int64  `json:"gidnumber"`
}

// CreateGroup creates a new group
func (c *Client) CreateGroup(ctx context.Context, name, description string) (*Group, error) {
	attrs := map[string]any{
		"name": []string{name},
	}

	if description != "" {
		attrs["description"] = []string{description}
	}

	req := NewCreateRequest(attrs)

	resp, err := c.doRequest(ctx, "POST", "/v1/group", req)
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return &Group{
		Name:        name,
		Description: description,
	}, nil
}

// GetGroup retrieves a group by ID
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	resp, err := c.doRequest(ctx, "GET", "/v1/group/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}

	var entry Entry
	if err := decodeResponse(resp, &entry); err != nil {
		return nil, err
	}

	// Ensure members is never nil
	members := entry.GetStringSlice("member")
	if members == nil {
		members = []string{}
	}
	var gidNumber *int64
	if parsed, ok := entry.GetInt64("gidnumber"); ok {
		gidNumber = &parsed
	}

	return &Group{
		UUID:        firstNonEmpty(entry.GetString("entryuuid"), entry.GetString("uuid")),
		Name:        entry.GetString("name"),
		SPN:         entry.GetString("spn"),
		Description: entry.GetString("description"),
		Mail:        entry.GetStringSlice("mail"),
		GIDNumber:   gidNumber,
		EntryManagedBy: entry.GetStringSlice("entry_managed_by"),
		Members:     members,
	}, nil
}

// UpdateGroup updates a group
func (c *Client) UpdateGroup(ctx context.Context, id string, name *string, description *string, mail []string, entryManagedBy []string, members []string) error {
	attrs := make(map[string]any)

	if name != nil {
		attrs["name"] = []string{*name}
	}

	if description != nil {
		attrs["description"] = []string{*description}
	}

	if mail != nil {
		attrs["mail"] = mail
	}

	if entryManagedBy != nil {
		attrs["entry_managed_by"] = entryManagedBy
	}

	if members != nil {
		attrs["member"] = members
	}

	req := NewUpdateRequest(attrs)

	resp, err := c.doRequest(ctx, "PATCH", "/v1/group/"+id, req)
	if err != nil {
		return fmt.Errorf("update group: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func (c *Client) SetGroupGIDNumber(ctx context.Context, id string, gidNumber *int64) error {
	body := map[string]any{}
	if gidNumber != nil {
		body["gidnumber"] = *gidNumber
	}
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/group/%s/_unix", id), body)
	if err != nil {
		return fmt.Errorf("set group gidnumber: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

func (c *Client) GetGroupUnixToken(ctx context.Context, id string) (*UnixGroupToken, error) {
	resp, err := c.doRequest(ctx, "GET", "/v1/group/"+id+"/_unix/_token", nil)
	if err != nil {
		return nil, fmt.Errorf("get group unix token: %w", err)
	}
	var token UnixGroupToken
	if err := decodeResponse(resp, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// DeleteGroup deletes a group
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/v1/group/"+id, nil)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// AddGroupMembers adds members to a group
func (c *Client) AddGroupMembers(ctx context.Context, groupID string, memberIDs []string) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/group/%s/_attr/member", groupID), memberIDs)
	if err != nil {
		return fmt.Errorf("add group members: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// RemoveGroupMembers removes members from a group
func (c *Client) RemoveGroupMembers(ctx context.Context, groupID string, memberIDs []string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/v1/group/%s/_attr/member", groupID), memberIDs)
	if err != nil {
		return fmt.Errorf("remove group members: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}
