package client

import (
	"context"
	"errors"
	"fmt"
)

type UnixUserToken struct {
	UUID        string `json:"uuid"`
	SPN         string `json:"spn"`
	Name        string `json:"name"`
	DisplayName string `json:"displayname"`
	GIDNumber   int64  `json:"gidnumber"`
	Shell       string `json:"shell"`
	Valid       bool   `json:"valid"`
}

func (c *Client) GetAccountUnixToken(ctx context.Context, id string) (*UnixUserToken, error) {
	resp, err := c.doRequest(ctx, "GET", "/v1/account/"+id+"/_unix/_token", nil)
	if err != nil {
		return nil, fmt.Errorf("get account unix token: %w", err)
	}
	var token UnixUserToken
	if err := decodeResponse(resp, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func UnixTokenUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrForbidden) || errors.Is(err, ErrUnauthorized) {
		return false
	}
	return true
}
