package provider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/ssoriche/terraform-provider-kanidm/internal/client"
)

var (
	_ resource.Resource                = (*oauth2ClientResource)(nil)
	_ resource.ResourceWithImportState = (*oauth2ClientResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*oauth2ClientResource)(nil)
)

func NewOAuth2BasicResource() resource.Resource {
	return &oauth2ClientResource{}
}


func NewOAuth2PublicResource() resource.Resource {
	return &oauth2ClientResource{public: true}
}

type oauth2ClientResource struct {
	client *client.Client
	public bool
}

type oauth2ResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	DisplayName  types.String `tfsdk:"displayname"`
	Origin       types.String `tfsdk:"origin"`
	RedirectURIs types.Set    `tfsdk:"redirect_uris"`
	ImagePath    types.String `tfsdk:"image_path"`
	ImageSHA256  types.String `tfsdk:"image_sha256"`
	ScopeMaps    types.Set    `tfsdk:"scope_map"`
	SupScopeMaps types.Set    `tfsdk:"sup_scope_map"`
	ClaimMaps    types.Set    `tfsdk:"claim_map"`
	PreferShortUsername         types.Bool   `tfsdk:"prefer_short_username"`
	AllowInsecureDisablePKCE    types.Bool   `tfsdk:"allow_insecure_client_disable_pkce"`
	JWTLegacyCryptoEnable       types.Bool   `tfsdk:"jwt_legacy_crypto_enable"`
	ClientSecret types.String
}

type oauth2BasicResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	DisplayName  types.String `tfsdk:"displayname"`
	Origin       types.String `tfsdk:"origin"`
	RedirectURIs types.Set    `tfsdk:"redirect_uris"`
	ImagePath    types.String `tfsdk:"image_path"`
	ImageSHA256  types.String `tfsdk:"image_sha256"`
	ScopeMaps    types.Set    `tfsdk:"scope_map"`
	SupScopeMaps types.Set    `tfsdk:"sup_scope_map"`
	ClaimMaps    types.Set    `tfsdk:"claim_map"`
	PreferShortUsername         types.Bool   `tfsdk:"prefer_short_username"`
	AllowInsecureDisablePKCE    types.Bool   `tfsdk:"allow_insecure_client_disable_pkce"`
	JWTLegacyCryptoEnable       types.Bool   `tfsdk:"jwt_legacy_crypto_enable"`
	ClientSecret types.String `tfsdk:"client_secret"`
}

type oauth2PublicResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	DisplayName  types.String `tfsdk:"displayname"`
	Origin       types.String `tfsdk:"origin"`
	RedirectURIs types.Set    `tfsdk:"redirect_uris"`
	ImagePath    types.String `tfsdk:"image_path"`
	ImageSHA256  types.String `tfsdk:"image_sha256"`
	ScopeMaps    types.Set    `tfsdk:"scope_map"`
	SupScopeMaps types.Set    `tfsdk:"sup_scope_map"`
	ClaimMaps    types.Set    `tfsdk:"claim_map"`
	PreferShortUsername         types.Bool   `tfsdk:"prefer_short_username"`
	AllowInsecureDisablePKCE    types.Bool   `tfsdk:"allow_insecure_client_disable_pkce"`
	JWTLegacyCryptoEnable       types.Bool   `tfsdk:"jwt_legacy_crypto_enable"`
}

type scopeMapModel struct {
	Group  types.String `tfsdk:"group"`
	Scopes types.Set    `tfsdk:"scopes"`
}

type claimMapModel struct {
	Name   types.String `tfsdk:"name"`
	Group  types.String `tfsdk:"group"`
	Values types.Set    `tfsdk:"values"`
	Join   types.String `tfsdk:"join"`
}

type stateGetter interface {
	Get(context.Context, any) diag.Diagnostics
}

type stateSetter interface {
	Set(context.Context, any) diag.Diagnostics
}

func resourceModelFromBasic(model oauth2BasicResourceModel) oauth2ResourceModel {
	return oauth2ResourceModel{
		ID:           model.ID,
		Name:         model.Name,
		DisplayName:  model.DisplayName,
		Origin:       model.Origin,
		RedirectURIs: model.RedirectURIs,
		ImagePath:    model.ImagePath,
		ImageSHA256:  model.ImageSHA256,
		ScopeMaps:    model.ScopeMaps,
		SupScopeMaps: model.SupScopeMaps,
		ClaimMaps:    model.ClaimMaps,
		PreferShortUsername: model.PreferShortUsername,
		AllowInsecureDisablePKCE: model.AllowInsecureDisablePKCE,
		JWTLegacyCryptoEnable: model.JWTLegacyCryptoEnable,
		ClientSecret: model.ClientSecret,
	}
}

func resourceModelFromPublic(model oauth2PublicResourceModel) oauth2ResourceModel {
	return oauth2ResourceModel{
		ID:           model.ID,
		Name:         model.Name,
		DisplayName:  model.DisplayName,
		Origin:       model.Origin,
		RedirectURIs: model.RedirectURIs,
		ImagePath:    model.ImagePath,
		ImageSHA256:  model.ImageSHA256,
		ScopeMaps:    model.ScopeMaps,
		SupScopeMaps: model.SupScopeMaps,
		ClaimMaps:    model.ClaimMaps,
		PreferShortUsername: model.PreferShortUsername,
		AllowInsecureDisablePKCE: model.AllowInsecureDisablePKCE,
		JWTLegacyCryptoEnable: model.JWTLegacyCryptoEnable,
		ClientSecret: types.StringNull(),
	}
}

func basicModelFromResource(model oauth2ResourceModel) oauth2BasicResourceModel {
	return oauth2BasicResourceModel{
		ID:           model.ID,
		Name:         model.Name,
		DisplayName:  model.DisplayName,
		Origin:       model.Origin,
		RedirectURIs: model.RedirectURIs,
		ImagePath:    model.ImagePath,
		ImageSHA256:  model.ImageSHA256,
		ScopeMaps:    model.ScopeMaps,
		SupScopeMaps: model.SupScopeMaps,
		ClaimMaps:    model.ClaimMaps,
		PreferShortUsername: model.PreferShortUsername,
		AllowInsecureDisablePKCE: model.AllowInsecureDisablePKCE,
		JWTLegacyCryptoEnable: model.JWTLegacyCryptoEnable,
		ClientSecret: model.ClientSecret,
	}
}

func publicModelFromResource(model oauth2ResourceModel) oauth2PublicResourceModel {
	return oauth2PublicResourceModel{
		ID:           model.ID,
		Name:         model.Name,
		DisplayName:  model.DisplayName,
		Origin:       model.Origin,
		RedirectURIs: model.RedirectURIs,
		ImagePath:    model.ImagePath,
		ImageSHA256:  model.ImageSHA256,
		ScopeMaps:    model.ScopeMaps,
		SupScopeMaps: model.SupScopeMaps,
		ClaimMaps:    model.ClaimMaps,
		PreferShortUsername: model.PreferShortUsername,
		AllowInsecureDisablePKCE: model.AllowInsecureDisablePKCE,
		JWTLegacyCryptoEnable: model.JWTLegacyCryptoEnable,
	}
}

func (r *oauth2ClientResource) getResourceModel(ctx context.Context, getter stateGetter, model *oauth2ResourceModel) diag.Diagnostics {
	if r.public {
		var publicModel oauth2PublicResourceModel
		diags := getter.Get(ctx, &publicModel)
		if !diags.HasError() {
			*model = resourceModelFromPublic(publicModel)
		}
		return diags
	}
	var basicModel oauth2BasicResourceModel
	diags := getter.Get(ctx, &basicModel)
	if !diags.HasError() {
		*model = resourceModelFromBasic(basicModel)
	}
	return diags
}

func (r *oauth2ClientResource) setResourceModel(ctx context.Context, setter stateSetter, model *oauth2ResourceModel) diag.Diagnostics {
	if r.public {
		model.ClientSecret = types.StringNull()
		publicModel := publicModelFromResource(*model)
		return setter.Set(ctx, &publicModel)
	}
	basicModel := basicModelFromResource(*model)
	return setter.Set(ctx, &basicModel)
}

func firstKnownString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func hashFileSHA256(filePath string) (string, error) {
	contents, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read file %q: %w", filePath, err)
	}
	sum := sha256.Sum256(contents)
	return fmt.Sprintf("%x", sum[:]), nil
}

func (r *oauth2ClientResource) resourceTypeName() string {
	if r.public {
		return "oauth2_public"
	}
	return "oauth2_basic"
}

func (r *oauth2ClientResource) resourceLabel() string {
	if r.public {
		return "OAuth2 Public Client"
	}
	return "OAuth2 Basic Client"
}

func (r *oauth2ClientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.resourceTypeName()
}


func (r *oauth2ClientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	description := "Manages a Kanidm OAuth2 basic (confidential) client."
	if r.public {
		description = "Manages a Kanidm OAuth2 public client."
	}
	attributes := map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "Stable Kanidm UUID for this OAuth2 client.",
			Computed:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "OAuth2 client name (client ID).",
			Required:            true,
		},
		"displayname": schema.StringAttribute{
			MarkdownDescription: "Display name of the OAuth2 client.",
			Required:            true,
		},
		"origin": schema.StringAttribute{
			MarkdownDescription: "Origin URL where the OAuth2 client application is hosted.",
			Required:            true,
		},
		"redirect_uris": schema.SetAttribute{
			MarkdownDescription: "Set of allowed redirect URIs for OAuth2 callbacks.",
			Optional:            true,
			ElementType:         types.StringType,
		},
		"prefer_short_username": schema.BoolAttribute{
			MarkdownDescription: "Whether Kanidm should emit the bare username in the preferred_username claim instead of the full SPN.",
			Optional:            true,
		},
		"allow_insecure_client_disable_pkce": schema.BoolAttribute{
			MarkdownDescription: "Whether this confidential client may disable PKCE. Only use for legacy clients that cannot support PKCE.",
			Optional:            true,
		},
		"jwt_legacy_crypto_enable": schema.BoolAttribute{
			MarkdownDescription: "Whether Kanidm should enable legacy JWT crypto compatibility for this client.",
			Optional:            true,
		},
		"image_path": schema.StringAttribute{
			MarkdownDescription: "Optional local path to an image file to upload.",
			Optional:            true,
		},
		"image_sha256": schema.StringAttribute{
			MarkdownDescription: "SHA-256 hash of the local image file last applied.",
			Computed:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
	}
	if !r.public {
		attributes["client_secret"] = schema.StringAttribute{
			MarkdownDescription: "Client secret for the OAuth2 basic client. Only available during creation.",
			Computed:            true,
			Sensitive:           true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: description,
		Attributes:          attributes,
		Blocks: map[string]schema.Block{
			"scope_map": schema.SetNestedBlock{
				MarkdownDescription: "Scope mappings that define which OAuth2 scopes are granted to members of specific groups.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"group": schema.StringAttribute{
							MarkdownDescription: "UUID of the Kanidm group to map scopes to.",
							Required:            true,
						},
						"scopes": schema.SetAttribute{
							MarkdownDescription: "Set of OAuth2 scopes to grant to group members.",
							Required:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"sup_scope_map": schema.SetNestedBlock{
				MarkdownDescription: "Supplemental scope mappings that are automatically granted and cannot be declined.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"group": schema.StringAttribute{
							MarkdownDescription: "UUID of the Kanidm group to map scopes to.",
							Required:            true,
						},
						"scopes": schema.SetAttribute{
							MarkdownDescription: "Set of OAuth2 scopes to grant to group members.",
							Required:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"claim_map": schema.SetNestedBlock{
				MarkdownDescription: "Claim mappings that define custom OIDC claims for members of specific groups.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "Name of the custom claim.",
							Required:            true,
						},
						"group": schema.StringAttribute{
							MarkdownDescription: "UUID of the Kanidm group to map claim values to.",
							Required:            true,
						},
						"values": schema.SetAttribute{
							MarkdownDescription: "Set of claim values to grant to group members.",
							Required:            true,
							ElementType:         types.StringType,
						},
						"join": schema.StringAttribute{
							MarkdownDescription: "Join strategy for this claim name. Valid values: csv, ssv, array.",
							Required:            true,
						},
					},
				},
			},
		},
	}
}

func (r *oauth2ClientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := configureResource(req, resp)
	if data == nil {
		return
	}
	r.client = data.client
}

func (r *oauth2ClientResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan oauth2ResourceModel
	resp.Diagnostics.Append(r.getResourceModel(ctx, req.Plan, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.ImagePath.IsNull() || plan.ImagePath.IsUnknown() || plan.ImagePath.ValueString() == "" {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("image_sha256"), types.StringNull())...)
	} else {
		hash, err := hashFileSHA256(plan.ImagePath.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error Hashing OAuth2 Image", err.Error())
			return
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("image_sha256"), types.StringValue(hash))...)
	}
	if !plan.ClaimMaps.IsNull() && !plan.ClaimMaps.IsUnknown() {
		var claimMaps []claimMapModel
		resp.Diagnostics.Append(plan.ClaimMaps.ElementsAs(ctx, &claimMaps, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		joinByName := make(map[string]string)
		for _, cm := range claimMaps {
			name := cm.Name.ValueString()
			join := cm.Join.ValueString()
			if existing, ok := joinByName[name]; ok && existing != join {
				resp.Diagnostics.AddError(
					"Inconsistent Claim Map Join",
					fmt.Sprintf("All claim_map blocks with name %q must use the same join strategy. Found both %q and %q.", name, existing, join),
				)
				return
			}
			joinByName[name] = join
		}
	}

	// Normalize scope_map, sup_scope_map, and claim_map inner lists to sorted order
	// so they match Kanidm's BTreeSet ordering and avoid perpetual diffs.
	if !plan.ScopeMaps.IsNull() && !plan.ScopeMaps.IsUnknown() {
		var scopeMaps []scopeMapModel
		resp.Diagnostics.Append(plan.ScopeMaps.ElementsAs(ctx, &scopeMaps, false)...)
		if !resp.Diagnostics.HasError() {
			for i := range scopeMaps {
				var scopes []string
				resp.Diagnostics.Append(scopeMaps[i].Scopes.ElementsAs(ctx, &scopes, false)...)
				if resp.Diagnostics.HasError() {
					return
				}
				sort.Strings(scopes)
				scopesList, diags := types.SetValueFrom(ctx, types.StringType, scopes)
				if diags.HasError() {
					resp.Diagnostics.Append(diags...)
					return
				}
				scopeMaps[i].Scopes = scopesList
			}
				scopeMapsSet, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
					"group": types.StringType, "scopes": types.SetType{ElemType: types.StringType},
				}}, scopeMaps)
			if diags.HasError() {
				resp.Diagnostics.Append(diags...)
				return
			}
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("scope_map"), scopeMapsSet)...)
		}
	}

	if !plan.SupScopeMaps.IsNull() && !plan.SupScopeMaps.IsUnknown() {
		var supScopeMaps []scopeMapModel
		resp.Diagnostics.Append(plan.SupScopeMaps.ElementsAs(ctx, &supScopeMaps, false)...)
		if !resp.Diagnostics.HasError() {
			for i := range supScopeMaps {
				var scopes []string
				resp.Diagnostics.Append(supScopeMaps[i].Scopes.ElementsAs(ctx, &scopes, false)...)
				if resp.Diagnostics.HasError() {
					return
				}
				sort.Strings(scopes)
				scopesList, diags := types.SetValueFrom(ctx, types.StringType, scopes)
				if diags.HasError() {
					resp.Diagnostics.Append(diags...)
					return
				}
				supScopeMaps[i].Scopes = scopesList
			}
				supScopeMapsSet, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
					"group": types.StringType, "scopes": types.SetType{ElemType: types.StringType},
				}}, supScopeMaps)
			if diags.HasError() {
				resp.Diagnostics.Append(diags...)
				return
			}
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("sup_scope_map"), supScopeMapsSet)...)
		}
	}

	if !plan.ClaimMaps.IsNull() && !plan.ClaimMaps.IsUnknown() {
		var claimMaps []claimMapModel
		resp.Diagnostics.Append(plan.ClaimMaps.ElementsAs(ctx, &claimMaps, false)...)
		if !resp.Diagnostics.HasError() {
			for i := range claimMaps {
				var values []string
				resp.Diagnostics.Append(claimMaps[i].Values.ElementsAs(ctx, &values, false)...)
				if resp.Diagnostics.HasError() {
					return
				}
				sort.Strings(values)
				valuesList, diags := types.SetValueFrom(ctx, types.StringType, values)
				if diags.HasError() {
					resp.Diagnostics.Append(diags...)
					return
				}
				claimMaps[i].Values = valuesList
			}
				claimMapsSet, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
					"name": types.StringType, "group": types.StringType,
					"values": types.SetType{ElemType: types.StringType}, "join": types.StringType,
				}}, claimMaps)
			if diags.HasError() {
				resp.Diagnostics.Append(diags...)
				return
			}
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("claim_map"), claimMapsSet)...)
		}
	}
}

func (r *oauth2ClientResource) resolveGroupSPN(ctx context.Context, identifier string) (string, error) {
	if strings.Contains(identifier, "@") {
		return identifier, nil
	}
	group, err := r.client.GetGroup(ctx, identifier)
	if err != nil {
		return "", fmt.Errorf("resolve group %q: %w", identifier, err)
	}
	if group.SPN != "" {
		return group.SPN, nil
	}
	if group.Name != "" {
		return group.Name, nil
	}
	return "", fmt.Errorf("group %q did not return a name or SPN", identifier)
}

func (r *oauth2ClientResource) resolveGroupUUID(ctx context.Context, identifier string) (string, error) {
	group, err := r.client.GetGroup(ctx, identifier)
	if err != nil {
		return "", fmt.Errorf("resolve group %q: %w", identifier, err)
	}
	if group.UUID == "" {
		return "", fmt.Errorf("group %q did not return a UUID", identifier)
	}
	return group.UUID, nil
}

func (r *oauth2ClientResource) applyOAuth2BasicState(ctx context.Context, model *oauth2ResourceModel, oauth2Client *client.OAuth2Client) error {
	if oauth2Client.UUID == "" {
		return errors.New("Kanidm did not return a UUID for the requested OAuth2 client")
	}
	model.ID = types.StringValue(oauth2Client.UUID)
	model.Name = types.StringValue(oauth2Client.Name)
	model.DisplayName = types.StringValue(oauth2Client.DisplayName)
	model.Origin = types.StringValue(oauth2Client.Origin)
	if oauth2Client.PreferShortUsernameSet {
		model.PreferShortUsername = types.BoolValue(oauth2Client.PreferShortUsername)
	} else {
		model.PreferShortUsername = types.BoolNull()
	}
	if oauth2Client.AllowInsecureDisablePKCESet {
		model.AllowInsecureDisablePKCE = types.BoolValue(oauth2Client.AllowInsecureDisablePKCE)
	} else {
		model.AllowInsecureDisablePKCE = types.BoolNull()
	}
	if oauth2Client.JWTLegacyCryptoEnableSet {
		model.JWTLegacyCryptoEnable = types.BoolValue(oauth2Client.JWTLegacyCryptoEnable)
	} else {
		model.JWTLegacyCryptoEnable = types.BoolNull()
	}
	if len(oauth2Client.RedirectURIs) > 0 {
		redirectURIsList, diags := types.SetValueFrom(ctx, types.StringType, oauth2Client.RedirectURIs)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		model.RedirectURIs = redirectURIsList
	} else {
		model.RedirectURIs = types.SetNull(types.StringType)
	}
	if len(oauth2Client.ScopeMaps) > 0 {
		scopeMapModels := make([]scopeMapModel, 0, len(oauth2Client.ScopeMaps))
		for _, sm := range oauth2Client.ScopeMaps {
			groupUUID, err := r.resolveGroupUUID(ctx, sm.Group)
			if err != nil {
				return fmt.Errorf("resolve scope map group %q: %w", sm.Group, err)
			}
			sortedScopes := make([]string, len(sm.Scopes))
			copy(sortedScopes, sm.Scopes)
			sort.Strings(sortedScopes)
				scopesList, diags := types.SetValueFrom(ctx, types.StringType, sortedScopes)
			if diags.HasError() {
				return errors.New(diags.Errors()[0].Summary())
			}
			scopeMapModels = append(scopeMapModels, scopeMapModel{Group: types.StringValue(groupUUID), Scopes: scopesList})
		}
		scopeMapsSet, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
			"group": types.StringType, "scopes": types.SetType{ElemType: types.StringType},
		}}, scopeMapModels)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		model.ScopeMaps = scopeMapsSet
	} else {
		model.ScopeMaps = types.SetNull(types.ObjectType{AttrTypes: map[string]attr.Type{
			"group": types.StringType, "scopes": types.SetType{ElemType: types.StringType},
		}})
	}
	if len(oauth2Client.SupScopeMaps) > 0 {
		supScopeMapModels := make([]scopeMapModel, 0, len(oauth2Client.SupScopeMaps))
		for _, sm := range oauth2Client.SupScopeMaps {
			groupUUID, err := r.resolveGroupUUID(ctx, sm.Group)
			if err != nil {
				return fmt.Errorf("resolve sup scope map group %q: %w", sm.Group, err)
			}
			sortedScopes := make([]string, len(sm.Scopes))
			copy(sortedScopes, sm.Scopes)
			sort.Strings(sortedScopes)
				scopesList, diags := types.SetValueFrom(ctx, types.StringType, sortedScopes)
			if diags.HasError() {
				return errors.New(diags.Errors()[0].Summary())
			}
			supScopeMapModels = append(supScopeMapModels, scopeMapModel{Group: types.StringValue(groupUUID), Scopes: scopesList})
		}
		supScopeMapsSet, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
			"group": types.StringType, "scopes": types.SetType{ElemType: types.StringType},
		}}, supScopeMapModels)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		model.SupScopeMaps = supScopeMapsSet
	} else {
		model.SupScopeMaps = types.SetNull(types.ObjectType{AttrTypes: map[string]attr.Type{
			"group": types.StringType, "scopes": types.SetType{ElemType: types.StringType},
		}})
	}
	if len(oauth2Client.ClaimMaps) > 0 {
		claimMapModels := make([]claimMapModel, 0, len(oauth2Client.ClaimMaps))
		for _, cm := range oauth2Client.ClaimMaps {
			groupUUID, err := r.resolveGroupUUID(ctx, cm.Group)
			if err != nil {
				return fmt.Errorf("resolve claim map group %q: %w", cm.Group, err)
			}
			sortedValues := make([]string, len(cm.Values))
			copy(sortedValues, cm.Values)
			sort.Strings(sortedValues)
			valuesList, diags := types.SetValueFrom(ctx, types.StringType, sortedValues)
			if diags.HasError() {
				return errors.New(diags.Errors()[0].Summary())
			}
			claimMapModels = append(claimMapModels, claimMapModel{
				Name: types.StringValue(cm.Name), Group: types.StringValue(groupUUID),
				Values: valuesList, Join: types.StringValue(cm.Join),
			})
		}
		claimMapsSet, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
			"name": types.StringType, "group": types.StringType,
			"values": types.SetType{ElemType: types.StringType}, "join": types.StringType,
		}}, claimMapModels)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		model.ClaimMaps = claimMapsSet
	} else {
		model.ClaimMaps = types.SetNull(types.ObjectType{AttrTypes: map[string]attr.Type{
			"name": types.StringType, "group": types.StringType,
			"values": types.SetType{ElemType: types.StringType}, "join": types.StringType,
		}})
	}
	if model.ImagePath.IsNull() || model.ImagePath.IsUnknown() || model.ImagePath.ValueString() == "" {
		model.ImageSHA256 = types.StringNull()
	}
	return nil
}

func (r *oauth2ClientResource) applyScopeMaps(ctx context.Context, rsName string, planScopeMaps types.Set) error {
	if planScopeMaps.IsNull() || planScopeMaps.IsUnknown() {
		return nil
	}
	var scopeMaps []scopeMapModel
	diags := planScopeMaps.ElementsAs(ctx, &scopeMaps, false)
	if diags.HasError() {
		return errors.New(diags.Errors()[0].Summary())
	}
	for _, scopeMap := range scopeMaps {
		var scopes []string
		diags := scopeMap.Scopes.ElementsAs(ctx, &scopes, false)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		groupSPN, err := r.resolveGroupSPN(ctx, scopeMap.Group.ValueString())
		if err != nil {
			return fmt.Errorf("resolve scope map group %q: %w", scopeMap.Group.ValueString(), err)
		}
		if err := r.client.SetOAuth2ScopeMap(ctx, rsName, groupSPN, scopes); err != nil {
			return fmt.Errorf("set scope map for group %q: %w", groupSPN, err)
		}
	}
	return nil
}

func (r *oauth2ClientResource) applySupScopeMaps(ctx context.Context, rsName string, planSupScopeMaps types.Set) error {
	if planSupScopeMaps.IsNull() || planSupScopeMaps.IsUnknown() {
		return nil
	}
	var supScopeMaps []scopeMapModel
	diags := planSupScopeMaps.ElementsAs(ctx, &supScopeMaps, false)
	if diags.HasError() {
		return errors.New(diags.Errors()[0].Summary())
	}
	for _, supScopeMap := range supScopeMaps {
		var scopes []string
		diags := supScopeMap.Scopes.ElementsAs(ctx, &scopes, false)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		groupSPN, err := r.resolveGroupSPN(ctx, supScopeMap.Group.ValueString())
		if err != nil {
			return fmt.Errorf("resolve sup scope map group %q: %w", supScopeMap.Group.ValueString(), err)
		}
		if err := r.client.SetOAuth2SupScopeMap(ctx, rsName, groupSPN, scopes); err != nil {
			return fmt.Errorf("set sup scope map for group %q: %w", groupSPN, err)
		}
	}
	return nil
}

func (r *oauth2ClientResource) applyClaimMaps(ctx context.Context, rsName string, planClaimMaps types.Set) error {
	if planClaimMaps.IsNull() || planClaimMaps.IsUnknown() {
		return nil
	}
	var claimMaps []claimMapModel
	diags := planClaimMaps.ElementsAs(ctx, &claimMaps, false)
	if diags.HasError() {
		return errors.New(diags.Errors()[0].Summary())
	}
	joinByName := make(map[string]string)
	for _, claimMap := range claimMaps {
		joinByName[claimMap.Name.ValueString()] = claimMap.Join.ValueString()
	}
	for _, claimMap := range claimMaps {
		var values []string
		diags := claimMap.Values.ElementsAs(ctx, &values, false)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		groupSPN, err := r.resolveGroupSPN(ctx, claimMap.Group.ValueString())
		if err != nil {
			return fmt.Errorf("resolve claim map group %q: %w", claimMap.Group.ValueString(), err)
		}
		if err := r.client.SetOAuth2ClaimMap(ctx, rsName, claimMap.Name.ValueString(), groupSPN, values); err != nil {
			return fmt.Errorf("set claim map for claim %q group %q: %w", claimMap.Name.ValueString(), groupSPN, err)
		}
	}
	for name, join := range joinByName {
		if err := r.client.SetOAuth2ClaimMapJoin(ctx, rsName, name, join); err != nil {
			return fmt.Errorf("set claim map join for %q: %w", name, err)
		}
	}
	return nil
}

func (r *oauth2ClientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan oauth2ResourceModel
	resp.Diagnostics.Append(r.getResourceModel(ctx, req.Plan, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Creating OAuth2 client", map[string]any{"name": plan.Name.ValueString(), "public": r.public})
	var oauth2Client *client.OAuth2Client
	var err error
	if r.public {
		oauth2Client, err = r.client.CreateOAuth2PublicClient(ctx, plan.Name.ValueString(), plan.DisplayName.ValueString(), plan.Origin.ValueString())
	} else {
		oauth2Client, err = r.client.CreateOAuth2BasicClient(ctx, plan.Name.ValueString(), plan.DisplayName.ValueString(), plan.Origin.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Error Creating "+r.resourceLabel(), err.Error())
		return
	}
	var redirectURIs []string
	if !plan.RedirectURIs.IsNull() && !plan.RedirectURIs.IsUnknown() {
		resp.Diagnostics.Append(plan.RedirectURIs.ElementsAs(ctx, &redirectURIs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	createOpts := client.UpdateOAuth2ClientOpts{
		DisplayName: plan.DisplayName.ValueString(),
		Origin:      plan.Origin.ValueString(),
		RedirectURIs: redirectURIs,
	}
	if !plan.PreferShortUsername.IsNull() && !plan.PreferShortUsername.IsUnknown() {
		value := plan.PreferShortUsername.ValueBool()
		createOpts.PreferShortUsername = &value
	}
	if !plan.AllowInsecureDisablePKCE.IsNull() && !plan.AllowInsecureDisablePKCE.IsUnknown() {
		value := plan.AllowInsecureDisablePKCE.ValueBool()
		createOpts.AllowInsecureDisablePKCE = &value
	}
	if !plan.JWTLegacyCryptoEnable.IsNull() && !plan.JWTLegacyCryptoEnable.IsUnknown() {
		value := plan.JWTLegacyCryptoEnable.ValueBool()
		createOpts.JWTLegacyCryptoEnable = &value
	}
	if err := r.client.UpdateOAuth2Client(ctx, oauth2Client.Name, createOpts); err != nil {
		resp.Diagnostics.AddError("Error Setting OAuth2 Configuration", err.Error())
		return
	}
	if err := r.applyScopeMaps(ctx, oauth2Client.Name, plan.ScopeMaps); err != nil {
		resp.Diagnostics.AddError("Error Setting Scope Maps", err.Error())
		return
	}
	if err := r.applySupScopeMaps(ctx, oauth2Client.Name, plan.SupScopeMaps); err != nil {
		resp.Diagnostics.AddError("Error Setting Supplemental Scope Maps", err.Error())
		return
	}
	if err := r.applyClaimMaps(ctx, oauth2Client.Name, plan.ClaimMaps); err != nil {
		resp.Diagnostics.AddError("Error Setting Claim Maps", err.Error())
		return
	}
	if !plan.ImagePath.IsNull() && !plan.ImagePath.IsUnknown() && plan.ImagePath.ValueString() != "" {
		if err := r.client.UploadOAuth2Image(ctx, oauth2Client.Name, plan.ImagePath.ValueString()); err != nil {
			resp.Diagnostics.AddError("Error Uploading OAuth2 Image", err.Error())
			return
		}
	}
	createdClient, err := r.client.ResolveOAuth2Client(ctx, oauth2Client.Name)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading OAuth2 Client", err.Error())
		return
	}
	if err := r.applyOAuth2BasicState(ctx, &plan, createdClient); err != nil {
		resp.Diagnostics.AddError("Error Reading OAuth2 Client", err.Error())
		return
	}
	if r.public {
		plan.ClientSecret = types.StringNull()
	} else {
		plan.ClientSecret = types.StringValue(oauth2Client.ClientSecret)
	}
	if plan.ImagePath.IsNull() || plan.ImagePath.IsUnknown() || plan.ImagePath.ValueString() == "" {
		plan.ImageSHA256 = types.StringNull()
	}
	resp.Diagnostics.Append(r.setResourceModel(ctx, &resp.State, &plan)...)
}

func (r *oauth2ClientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state oauth2ResourceModel
	resp.Diagnostics.Append(r.getResourceModel(ctx, req.State, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Reading OAuth2 client", map[string]any{"id": state.ID.ValueString(), "public": r.public})
	oauth2Client, err := r.client.ResolveOAuth2Client(ctx, firstKnownString(state.ID.ValueString(), state.Name.ValueString()))
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading OAuth2 Client", err.Error())
		return
	}
	if oauth2Client.IsPublic != r.public {
		expectedType := "basic (confidential)"
		actualType := "public"
		if r.public {
			expectedType = "public"
			actualType = "basic (confidential)"
		}
		resp.Diagnostics.AddError("Invalid Client Type", fmt.Sprintf("Expected OAuth2 %s client but found %s client.", expectedType, actualType))
		return
	}
	if err := r.applyOAuth2BasicState(ctx, &state, oauth2Client); err != nil {
		resp.Diagnostics.AddError("Error Reading OAuth2 Client", err.Error())
		return
	}
	if r.public {
		state.ClientSecret = types.StringNull()
	} else if state.ClientSecret.IsNull() || state.ClientSecret.ValueString() == "" {
		secret, err := r.client.GetOAuth2BasicSecret(ctx, oauth2Client.Name)
		if err != nil {
			state.ClientSecret = types.StringNull()
		} else {
			state.ClientSecret = types.StringValue(secret)
		}
	}
	resp.Diagnostics.Append(r.setResourceModel(ctx, &resp.State, &state)...)
}

func scopeMapKey(group string, scopes []string) string {
	sortedScopes := make([]string, len(scopes))
	copy(sortedScopes, scopes)
	sort.Strings(sortedScopes)
	return group + "::" + strings.Join(sortedScopes, ",")
}

func claimMapKey(name, group, join string, values []string) string {
	sortedValues := make([]string, len(values))
	copy(sortedValues, values)
	sort.Strings(sortedValues)
	return name + "::" + group + "::" + join + "::" + strings.Join(sortedValues, ",")
}

func (r *oauth2ClientResource) diffScopeMaps(ctx context.Context, oldSet, newSet types.Set) (toDelete, toCreate []scopeMapModel, err error) {
	var oldMaps, newMaps []scopeMapModel
	if !oldSet.IsNull() && !oldSet.IsUnknown() {
		diags := oldSet.ElementsAs(ctx, &oldMaps, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
	}
	if !newSet.IsNull() && !newSet.IsUnknown() {
		diags := newSet.ElementsAs(ctx, &newMaps, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
	}
	oldByGroup := make(map[string][]string)
	for _, sm := range oldMaps {
		var scopes []string
		diags := sm.Scopes.ElementsAs(ctx, &scopes, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
		oldByGroup[sm.Group.ValueString()] = scopes
	}
	newByGroup := make(map[string][]string)
	for _, sm := range newMaps {
		var scopes []string
		diags := sm.Scopes.ElementsAs(ctx, &scopes, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
		newByGroup[sm.Group.ValueString()] = scopes
	}
	for group, scopes := range oldByGroup {
		if newScopes, exists := newByGroup[group]; !exists || scopeMapKey(group, scopes) != scopeMapKey(group, newScopes) {
			scopesList, diags := types.SetValueFrom(ctx, types.StringType, scopes)
			if diags.HasError() {
				return nil, nil, errors.New(diags.Errors()[0].Summary())
			}
			toDelete = append(toDelete, scopeMapModel{Group: types.StringValue(group), Scopes: scopesList})
		}
	}
	for group, scopes := range newByGroup {
		if oldScopes, exists := oldByGroup[group]; !exists || scopeMapKey(group, scopes) != scopeMapKey(group, oldScopes) {
			scopesList, diags := types.SetValueFrom(ctx, types.StringType, scopes)
			if diags.HasError() {
				return nil, nil, errors.New(diags.Errors()[0].Summary())
			}
			toCreate = append(toCreate, scopeMapModel{Group: types.StringValue(group), Scopes: scopesList})
		}
	}
	return toDelete, toCreate, nil
}

func (r *oauth2ClientResource) diffClaimMaps(ctx context.Context, oldSet, newSet types.Set) (toDelete, toCreate []claimMapModel, err error) {
	var oldMaps, newMaps []claimMapModel
	if !oldSet.IsNull() && !oldSet.IsUnknown() {
		diags := oldSet.ElementsAs(ctx, &oldMaps, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
	}
	if !newSet.IsNull() && !newSet.IsUnknown() {
		diags := newSet.ElementsAs(ctx, &newMaps, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
	}
	oldByKey := make(map[string]claimMapModel)
	for _, cm := range oldMaps {
		var values []string
		diags := cm.Values.ElementsAs(ctx, &values, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
		oldByKey[claimMapKey(cm.Name.ValueString(), cm.Group.ValueString(), cm.Join.ValueString(), values)] = cm
	}
	newByKey := make(map[string]claimMapModel)
	for _, cm := range newMaps {
		var values []string
		diags := cm.Values.ElementsAs(ctx, &values, false)
		if diags.HasError() {
			return nil, nil, errors.New(diags.Errors()[0].Summary())
		}
		newByKey[claimMapKey(cm.Name.ValueString(), cm.Group.ValueString(), cm.Join.ValueString(), values)] = cm
	}
	for key, cm := range oldByKey {
		if _, exists := newByKey[key]; !exists {
			toDelete = append(toDelete, cm)
		}
	}
	for key, cm := range newByKey {
		if _, exists := oldByKey[key]; !exists {
			toCreate = append(toCreate, cm)
		}
	}
	return toDelete, toCreate, nil
}

func (r *oauth2ClientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state oauth2ResourceModel
	resp.Diagnostics.Append(r.getResourceModel(ctx, req.Plan, &plan)...)
	resp.Diagnostics.Append(r.getResourceModel(ctx, req.State, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resolvedClient, err := r.client.ResolveOAuth2Client(ctx, firstKnownString(state.ID.ValueString(), state.Name.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Error Resolving OAuth2 Client", err.Error())
		return
	}
	if resolvedClient.IsPublic != r.public {
		expectedType := "basic (confidential)"
		actualType := "public"
		if r.public {
			expectedType = "public"
			actualType = "basic (confidential)"
		}
		resp.Diagnostics.AddError("Invalid Client Type", fmt.Sprintf("Expected OAuth2 %s client but found %s client.", expectedType, actualType))
		return
	}
	var redirectURIs []string
	if !plan.RedirectURIs.IsNull() && !plan.RedirectURIs.IsUnknown() {
		resp.Diagnostics.Append(plan.RedirectURIs.ElementsAs(ctx, &redirectURIs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	nameChanged := !plan.Name.Equal(state.Name)
	var newName *string
	if nameChanged {
		n := plan.Name.ValueString()
		newName = &n
	}
	updateOpts := client.UpdateOAuth2ClientOpts{
		NewName:      newName,
		DisplayName:  plan.DisplayName.ValueString(),
		Origin:       plan.Origin.ValueString(),
		RedirectURIs: redirectURIs,
	}
	if !plan.PreferShortUsername.Equal(state.PreferShortUsername) && !plan.PreferShortUsername.IsNull() && !plan.PreferShortUsername.IsUnknown() {
		value := plan.PreferShortUsername.ValueBool()
		updateOpts.PreferShortUsername = &value
	}
	if !plan.AllowInsecureDisablePKCE.Equal(state.AllowInsecureDisablePKCE) && !plan.AllowInsecureDisablePKCE.IsNull() && !plan.AllowInsecureDisablePKCE.IsUnknown() {
		value := plan.AllowInsecureDisablePKCE.ValueBool()
		updateOpts.AllowInsecureDisablePKCE = &value
	}
	if !plan.JWTLegacyCryptoEnable.Equal(state.JWTLegacyCryptoEnable) && !plan.JWTLegacyCryptoEnable.IsNull() && !plan.JWTLegacyCryptoEnable.IsUnknown() {
		value := plan.JWTLegacyCryptoEnable.ValueBool()
		updateOpts.JWTLegacyCryptoEnable = &value
	}
	if err := r.client.UpdateOAuth2Client(ctx, resolvedClient.Name, updateOpts); err != nil {
		resp.Diagnostics.AddError("Error Updating OAuth2 Client", err.Error())
		return
	}
	effectiveName := resolvedClient.Name
	if nameChanged {
		effectiveName = plan.Name.ValueString()
	}
	scopeMapsToDelete, scopeMapsToCreate, err := r.diffScopeMaps(ctx, state.ScopeMaps, plan.ScopeMaps)
	if err != nil {
		resp.Diagnostics.AddError("Error Diffing Scope Maps", err.Error())
		return
	}
	for _, sm := range scopeMapsToDelete {
		groupSPN, err := r.resolveGroupSPN(ctx, sm.Group.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error Resolving Scope Map Group", err.Error())
			return
		}
		if err := r.client.DeleteOAuth2ScopeMap(ctx, effectiveName, groupSPN); err != nil {
			resp.Diagnostics.AddError("Error Deleting Scope Map", err.Error())
			return
		}
	}
	for _, sm := range scopeMapsToCreate {
		var scopes []string
		resp.Diagnostics.Append(sm.Scopes.ElementsAs(ctx, &scopes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		groupSPN, err := r.resolveGroupSPN(ctx, sm.Group.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error Resolving Scope Map Group", err.Error())
			return
		}
		if err := r.client.SetOAuth2ScopeMap(ctx, effectiveName, groupSPN, scopes); err != nil {
			resp.Diagnostics.AddError("Error Setting Scope Map", err.Error())
			return
		}
	}
	supScopeMapsToDelete, supScopeMapsToCreate, err := r.diffScopeMaps(ctx, state.SupScopeMaps, plan.SupScopeMaps)
	if err != nil {
		resp.Diagnostics.AddError("Error Diffing Supplemental Scope Maps", err.Error())
		return
	}
	for _, sm := range supScopeMapsToDelete {
		groupSPN, err := r.resolveGroupSPN(ctx, sm.Group.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error Resolving Sup Scope Map Group", err.Error())
			return
		}
		if err := r.client.DeleteOAuth2SupScopeMap(ctx, effectiveName, groupSPN); err != nil {
			resp.Diagnostics.AddError("Error Deleting Sup Scope Map", err.Error())
			return
		}
	}
	for _, sm := range supScopeMapsToCreate {
		var scopes []string
		resp.Diagnostics.Append(sm.Scopes.ElementsAs(ctx, &scopes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		groupSPN, err := r.resolveGroupSPN(ctx, sm.Group.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error Resolving Sup Scope Map Group", err.Error())
			return
		}
		if err := r.client.SetOAuth2SupScopeMap(ctx, effectiveName, groupSPN, scopes); err != nil {
			resp.Diagnostics.AddError("Error Setting Sup Scope Map", err.Error())
			return
		}
	}
	claimMapsToDelete, claimMapsToCreate, err := r.diffClaimMaps(ctx, state.ClaimMaps, plan.ClaimMaps)
	if err != nil {
		resp.Diagnostics.AddError("Error Diffing Claim Maps", err.Error())
		return
	}
	for _, cm := range claimMapsToDelete {
		groupSPN, err := r.resolveGroupSPN(ctx, cm.Group.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error Resolving Claim Map Group", err.Error())
			return
		}
		if err := r.client.DeleteOAuth2ClaimMap(ctx, effectiveName, cm.Name.ValueString(), groupSPN); err != nil {
			resp.Diagnostics.AddError("Error Deleting Claim Map", err.Error())
			return
		}
	}
	for _, cm := range claimMapsToCreate {
		var values []string
		resp.Diagnostics.Append(cm.Values.ElementsAs(ctx, &values, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		groupSPN, err := r.resolveGroupSPN(ctx, cm.Group.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error Resolving Claim Map Group", err.Error())
			return
		}
		if err := r.client.SetOAuth2ClaimMap(ctx, effectiveName, cm.Name.ValueString(), groupSPN, values); err != nil {
			resp.Diagnostics.AddError("Error Setting Claim Map", err.Error())
			return
		}
	}
	// Set join strategies after creating claim maps, since Kanidm may reset the
	// join strategy to default when the last group mapping for a claim is deleted.
	joinStrategies := make(map[string]string)
	for _, cm := range claimMapsToCreate {
		joinStrategies[cm.Name.ValueString()] = cm.Join.ValueString()
	}
	for name, join := range joinStrategies {
		if err := r.client.SetOAuth2ClaimMapJoin(ctx, effectiveName, name, join); err != nil {
			resp.Diagnostics.AddError("Error Setting Claim Map Join", err.Error())
			return
		}
	}
	if plan.ImagePath.IsNull() || plan.ImagePath.IsUnknown() || plan.ImagePath.ValueString() == "" {
		if !state.ImageSHA256.IsNull() && !state.ImageSHA256.IsUnknown() && state.ImageSHA256.ValueString() != "" {
			if err := r.client.DeleteOAuth2Image(ctx, effectiveName); err != nil {
				resp.Diagnostics.AddError("Error Deleting OAuth2 Image", err.Error())
				return
			}
		}
	} else if !plan.ImageSHA256.Equal(state.ImageSHA256) {
		if err := r.client.UploadOAuth2Image(ctx, effectiveName, plan.ImagePath.ValueString()); err != nil {
			resp.Diagnostics.AddError("Error Uploading OAuth2 Image", err.Error())
			return
		}
	}
	updatedClient, err := r.client.ResolveOAuth2Client(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading OAuth2 Client", err.Error())
		return
	}
	if err := r.applyOAuth2BasicState(ctx, &plan, updatedClient); err != nil {
		resp.Diagnostics.AddError("Error Reading OAuth2 Client", err.Error())
		return
	}
	if r.public {
		plan.ClientSecret = types.StringNull()
	} else {
		plan.ClientSecret = state.ClientSecret
	}
	if plan.ImagePath.IsNull() || plan.ImagePath.IsUnknown() || plan.ImagePath.ValueString() == "" {
		plan.ImageSHA256 = types.StringNull()
	}
	resp.Diagnostics.Append(r.setResourceModel(ctx, &resp.State, &plan)...)
}

func (r *oauth2ClientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state oauth2ResourceModel
	resp.Diagnostics.Append(r.getResourceModel(ctx, req.State, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resolvedClient, err := r.client.ResolveOAuth2Client(ctx, firstKnownString(state.ID.ValueString(), state.Name.ValueString()))
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			return
		}
		resp.Diagnostics.AddError("Error Resolving OAuth2 Client", err.Error())
		return
	}
	if resolvedClient.IsPublic != r.public {
		return
	}
	if err := r.client.DeleteOAuth2Client(ctx, resolvedClient.Name); err != nil {
		if errors.Is(err, client.ErrNotFound) {
			return
		}
		resp.Diagnostics.AddError("Error Deleting OAuth2 Client", err.Error())
		return
	}
}

func (r *oauth2ClientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	if r.public {
		return
	}
	resp.Diagnostics.AddWarning(
		"Client Secret Not Available",
		"The client secret for this OAuth2 basic client is not available after import. "+
			"If you need the secret, you must regenerate it manually using the Kanidm CLI.",
	)
}
