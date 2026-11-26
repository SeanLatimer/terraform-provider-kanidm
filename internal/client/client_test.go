package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Kanidm answers a GET for a single entry with HTTP 200 and a null body when
// nothing matches the id or the token cannot read the entry.
func TestGetByIDNullBodyIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("null"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "token")
	ctx := context.Background()

	if _, err := c.GetGroup(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetGroup: got %v, want ErrNotFound", err)
	}
	if _, err := c.GetPerson(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPerson: got %v, want ErrNotFound", err)
	}
	if _, err := c.GetServiceAccount(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetServiceAccount: got %v, want ErrNotFound", err)
	}
	if _, err := c.GetOAuth2Client(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetOAuth2Client: got %v, want ErrNotFound", err)
	}
}

func TestGetGroupEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/group/devs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"attrs":{"uuid":["00000000-0000-0000-0000-0000000000aa"],"name":["devs"],"spn":["devs@idm.example.com"]}}`))
	}))
	defer srv.Close()

	group, err := NewClient(srv.URL, "token").GetGroup(context.Background(), "devs")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if group.UUID != "00000000-0000-0000-0000-0000000000aa" || group.SPN != "devs@idm.example.com" {
		t.Errorf("GetGroup: got uuid %q spn %q", group.UUID, group.SPN)
	}
}
