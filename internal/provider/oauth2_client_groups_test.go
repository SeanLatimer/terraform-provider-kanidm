package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ssoriche/terraform-provider-kanidm/internal/client"
)

const (
	devsUUID = "00000000-0000-0000-0000-0000000000aa"
	devsSPN  = "devs@idm.example.com"
)

// groupServer serves GET /v1/group/{id}: "devs" by name, SPN or UUID when
// readable is true, otherwise the null body Kanidm returns for an entry the
// token cannot read. Any other id gets HTTP 500.
func groupServer(t *testing.T, readable bool, calls *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		switch strings.TrimPrefix(r.URL.Path, "/v1/group/") {
		case "devs", devsSPN, devsUUID:
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !readable {
			_, _ = w.Write([]byte("null"))
			return
		}
		_, _ = w.Write([]byte(`{"attrs":{"uuid":["` + devsUUID + `"],"name":["devs"],"spn":["` + devsSPN + `"]}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestResource(t *testing.T, readable bool) (*oauth2ClientResource, *int32) {
	t.Helper()
	var calls int32
	srv := groupServer(t, readable, &calls)
	return &oauth2ClientResource{client: client.NewClient(srv.URL, "token")}, &calls
}

func TestGroupStateValue(t *testing.T) {
	tests := []struct {
		name      string
		readable  bool
		prior     []string
		want      string
		wantCalls int32
	}{
		{name: "config uses the SPN", readable: true, prior: []string{devsSPN}, want: devsSPN},
		{name: "config uses the name", readable: true, prior: []string{"devs"}, want: "devs"},
		{name: "config uses the name, other case", readable: true, prior: []string{"Devs"}, want: "Devs"},
		{name: "config uses the SPN, other case", readable: true, prior: []string{"devs@IDM.example.com"}, want: "devs@IDM.example.com"},
		{name: "config uses the UUID", readable: true, prior: []string{devsUUID}, want: devsUUID, wantCalls: 1},
		{name: "no prior value, readable", readable: true, want: devsUUID, wantCalls: 1},
		{name: "no prior value, unreadable", readable: false, want: devsSPN, wantCalls: 1},
		{name: "config uses the SPN, unreadable", readable: false, prior: []string{devsSPN}, want: devsSPN},
		{name: "config uses the name, unreadable", readable: false, prior: []string{"devs"}, want: "devs"},
		{name: "another group's name is not a match", readable: true, prior: []string{"ops"}, want: devsUUID, wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, calls := newTestResource(t, tt.readable)
			prior := make(map[string]string)
			for _, p := range tt.prior {
				prior[strings.ToLower(p)] = p
			}
			got, err := r.groupStateValue(context.Background(), devsSPN, prior)
			if err != nil {
				t.Fatalf("groupStateValue: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if *calls != tt.wantCalls {
				t.Errorf("group lookups = %d, want %d", *calls, tt.wantCalls)
			}
		})
	}
}

func TestGroupStateValueServerError(t *testing.T) {
	r, _ := newTestResource(t, true)
	if _, err := r.groupStateValue(context.Background(), "other@idm.example.com", nil); err == nil {
		t.Fatal("want an error for HTTP 500, got nil")
	}
}

func TestResolveGroupSPN(t *testing.T) {
	tests := []struct {
		name       string
		readable   bool
		identifier string
		want       string
		wantErr    bool
	}{
		{name: "SPN is used as is", readable: false, identifier: devsSPN, want: devsSPN},
		{name: "readable name", readable: true, identifier: "devs", want: devsSPN},
		{name: "readable UUID", readable: true, identifier: devsUUID, want: devsSPN},
		{name: "unreadable name passes through", readable: false, identifier: "devs", want: "devs"},
		{name: "unreadable UUID is refused", readable: false, identifier: devsUUID, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestResource(t, tt.readable)
			got, err := r.resolveGroupSPN(context.Background(), tt.identifier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckGroupReadable(t *testing.T) {
	tests := []struct {
		name     string
		readable bool
		group    string
		wantErr  bool
	}{
		{name: "readable UUID", readable: true, group: devsUUID},
		{name: "unreadable UUID", readable: false, group: devsUUID, wantErr: true},
		{name: "name needs no read", readable: false, group: "devs"},
		{name: "SPN needs no read", readable: false, group: devsSPN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestResource(t, tt.readable)
			err := r.checkGroupReadable(context.Background(), tt.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

var (
	scopeMapType = types.ObjectType{AttrTypes: map[string]attr.Type{
		"group": types.StringType, "scopes": types.SetType{ElemType: types.StringType},
	}}
	claimMapType = types.ObjectType{AttrTypes: map[string]attr.Type{
		"name": types.StringType, "group": types.StringType,
		"values": types.SetType{ElemType: types.StringType}, "join": types.StringType,
	}}
)

func scopeMapSet(t *testing.T, group string) types.Set {
	t.Helper()
	scopes, _ := types.SetValueFrom(context.Background(), types.StringType, []string{"openid"})
	set, diags := types.SetValueFrom(context.Background(), scopeMapType, []scopeMapModel{{Group: types.StringValue(group), Scopes: scopes}})
	if diags.HasError() {
		t.Fatal(diags)
	}
	return set
}

func claimMapSet(t *testing.T, group string) types.Set {
	t.Helper()
	values, _ := types.SetValueFrom(context.Background(), types.StringType, []string{"admin"})
	set, diags := types.SetValueFrom(context.Background(), claimMapType, []claimMapModel{{
		Name: types.StringValue("role"), Group: types.StringValue(group), Values: values, Join: types.StringValue("array"),
	}})
	if diags.HasError() {
		t.Fatal(diags)
	}
	return set
}

func setGroups(t *testing.T, set types.Set) []string {
	t.Helper()
	var groups []string
	for _, g := range priorGroups(context.Background(), set) {
		groups = append(groups, g)
	}
	return groups
}

// applyOAuth2BasicState keeps the configured form of each map's group even
// when the token cannot read groups, for all three map kinds.
func TestApplyOAuth2BasicStateKeepsConfiguredGroups(t *testing.T) {
	r, calls := newTestResource(t, false)
	model := &oauth2ResourceModel{
		ImagePath:    types.StringNull(),
		ScopeMaps:    scopeMapSet(t, "devs"),
		SupScopeMaps: scopeMapSet(t, devsSPN),
		ClaimMaps:    claimMapSet(t, "devs"),
	}
	apiClient := &client.OAuth2Client{
		UUID:         "11111111-1111-1111-1111-111111111111",
		Name:         "app",
		ScopeMaps:    []client.OAuth2ScopeMap{{Group: devsSPN, Scopes: []string{"openid"}}},
		SupScopeMaps: []client.OAuth2ScopeMap{{Group: devsSPN, Scopes: []string{"openid"}}},
		ClaimMaps:    []client.OAuth2ClaimMap{{Name: "role", Group: devsSPN, Values: []string{"admin"}, Join: "array"}},
	}
	if err := r.applyOAuth2BasicState(context.Background(), model, apiClient); err != nil {
		t.Fatalf("applyOAuth2BasicState: %v", err)
	}
	if got := setGroups(t, model.ScopeMaps); len(got) != 1 || got[0] != "devs" {
		t.Errorf("scope_map groups = %v, want [devs]", got)
	}
	if got := setGroups(t, model.SupScopeMaps); len(got) != 1 || got[0] != devsSPN {
		t.Errorf("sup_scope_map groups = %v, want [%s]", got, devsSPN)
	}
	if got := setGroups(t, model.ClaimMaps); len(got) != 1 || got[0] != "devs" {
		t.Errorf("claim_map groups = %v, want [devs]", got)
	}
	if *calls != 0 {
		t.Errorf("group lookups = %d, want 0", *calls)
	}
}

// With a UUID in the prior state and a readable group, state keeps the UUID
// (the behaviour before this change).
func TestApplyOAuth2BasicStateKeepsUUID(t *testing.T) {
	r, _ := newTestResource(t, true)
	model := &oauth2ResourceModel{ImagePath: types.StringNull(), ScopeMaps: scopeMapSet(t, devsUUID)}
	apiClient := &client.OAuth2Client{
		UUID:      "11111111-1111-1111-1111-111111111111",
		Name:      "app",
		ScopeMaps: []client.OAuth2ScopeMap{{Group: devsSPN, Scopes: []string{"openid"}}},
	}
	if err := r.applyOAuth2BasicState(context.Background(), model, apiClient); err != nil {
		t.Fatalf("applyOAuth2BasicState: %v", err)
	}
	if got := setGroups(t, model.ScopeMaps); len(got) != 1 || got[0] != devsUUID {
		t.Errorf("scope_map groups = %v, want [%s]", got, devsUUID)
	}
}
