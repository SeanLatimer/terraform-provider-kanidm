package provider

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/ssoriche/terraform-provider-kanidm/internal/client"
)

var (
	_ resource.Resource                = (*serviceAccountResource)(nil)
	_ resource.ResourceWithImportState = (*serviceAccountResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*serviceAccountResource)(nil)
)

func NewServiceAccountResource() resource.Resource {
	return &serviceAccountResource{}
}

type serviceAccountResource struct {
	client *client.Client
}

type serviceAccountResourceModel struct {
	Name           types.String `tfsdk:"name"`
	ID             types.String `tfsdk:"id"`
	DisplayName    types.String `tfsdk:"displayname"`
	Mail           types.List   `tfsdk:"mail"`
	PosixEnabled   types.Bool   `tfsdk:"posix_enabled"`
	GIDNumber      types.Int64  `tfsdk:"gidnumber"`
	Shell          types.String `tfsdk:"shell"`
	APIToken       types.String `tfsdk:"api_token"`
	EntryManagedBy types.Set    `tfsdk:"entry_managed_by"`
	ValidFrom      types.String `tfsdk:"valid_from"`
	ExpireAt       types.String `tfsdk:"expire_at"`
}

func (r *serviceAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *serviceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Manages a Kanidm service account.

Service accounts are used for automated systems and applications to authenticate with Kanidm.
An API token is automatically generated on creation and can be used for authentication.

## Example Usage

` + "```hcl" + `
resource "kanidm_service_account" "terraform" {
  name        = "terraform-automation"
  displayname = "Terraform Automation Account"
}

# Store the API token in 1Password or another secret manager
output "terraform_token" {
  value     = kanidm_service_account.terraform.api_token
  sensitive = true
}
` + "```" + `

**Important:** The API token is only available during creation and cannot be recovered later.
Store it securely immediately after creation.`,

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Service account name. This can be changed outside Terraform, but is tracked via the stable UUID in `id`.",
				Required:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Stable Kanidm UUID for this service account. This value is computed after creation/import and used to keep the resource linked across external renames.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"displayname": schema.StringAttribute{
				MarkdownDescription: "Display name for the service account. This is shown in the Kanidm UI and logs.",
				Required:            true,
			},
			"mail": schema.ListAttribute{
				MarkdownDescription: "Email addresses for the service account.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"posix_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether POSIX support is enabled for the service account. Enabling without a gidnumber lets Kanidm generate one automatically. Disabling after enablement is not currently supported.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"gidnumber": schema.Int64Attribute{
				MarkdownDescription: "Optional POSIX gidnumber for the service account. Computed after POSIX is enabled, even when Kanidm generates the value.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"shell": schema.StringAttribute{
				MarkdownDescription: "Optional login shell for the POSIX-enabled service account.",
				Optional:            true,
				Computed:            true,
			},
			"api_token": schema.StringAttribute{
				MarkdownDescription: "API token for the service account. **Only available during creation.** " +
					"Store this token securely as it cannot be retrieved later.",
				Computed:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"entry_managed_by": schema.SetAttribute{
				MarkdownDescription: "Set of account or group IDs that can manage this service account. " +
					"This allows delegated administration, including API token generation. " +
					"**Required by Kanidm.** Use fully-qualified names (e.g., `terraform-admin@idm.s8i.ca`).",
				Required:    true,
				ElementType: types.StringType,
			},
			"valid_from": schema.StringAttribute{
				MarkdownDescription: "Earliest RFC3339 time when the service account can authenticate. Use `null` to leave unset.",
				Optional:            true,
			},
			"expire_at": schema.StringAttribute{
				MarkdownDescription: "RFC3339 time when the service account expires. Use `null` to leave unset.",
				Optional:            true,
			},
		},
	}
}

func validateServiceAccountTimestamp(attrName string, value types.String) error {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, value.ValueString()); err != nil {
		return errors.New(attrName + " must be a valid RFC3339 timestamp")
	}
	return nil
}

func validateServiceAccountPOSIX(plan serviceAccountResourceModel) error {
	posixEnabled := (!plan.PosixEnabled.IsNull() && !plan.PosixEnabled.IsUnknown() && plan.PosixEnabled.ValueBool()) || (!plan.GIDNumber.IsNull() && !plan.GIDNumber.IsUnknown()) || (!plan.Shell.IsNull() && !plan.Shell.IsUnknown() && plan.Shell.ValueString() != "")
	if !posixEnabled {
		return nil
	}
	if !plan.PosixEnabled.IsNull() && !plan.PosixEnabled.IsUnknown() && !plan.PosixEnabled.ValueBool() {
		return errors.New("gidnumber and shell require posix_enabled = true")
	}
	return nil
}

func (r *serviceAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := configureResource(req, resp)
	if data == nil {
		return
	}

	r.client = data.client
}

func (r *serviceAccountResource) resolveManagerSPN(ctx context.Context, identifier string) (string, error) {
	if identifier == "" {
		return "", nil
	}
	if person, err := r.client.GetPerson(ctx, identifier); err == nil {
		if person.SPN != "" {
			return person.SPN, nil
		}
		if person.Name != "" {
			return person.Name, nil
		}
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	}
	if serviceAccount, err := r.client.GetServiceAccount(ctx, identifier); err == nil {
		if serviceAccount.SPN != "" {
			return serviceAccount.SPN, nil
		}
		if serviceAccount.Name != "" {
			return serviceAccount.Name, nil
		}
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	}
	if group, err := r.client.GetGroup(ctx, identifier); err == nil {
		if group.SPN != "" {
			return group.SPN, nil
		}
		if group.Name != "" {
			return group.Name, nil
		}
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	}
	return "", client.ErrNotFound
}

func (r *serviceAccountResource) resolveManagerUUID(ctx context.Context, identifier string) (string, error) {
	if identifier == "" {
		return "", nil
	}
	if person, err := r.client.GetPerson(ctx, identifier); err == nil {
		if person.UUID != "" {
			return person.UUID, nil
		}
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	}
	if serviceAccount, err := r.client.GetServiceAccount(ctx, identifier); err == nil {
		if serviceAccount.UUID != "" {
			return serviceAccount.UUID, nil
		}
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	}
	if group, err := r.client.GetGroup(ctx, identifier); err == nil {
		if group.UUID != "" {
			return group.UUID, nil
		}
	} else if !errors.Is(err, client.ErrNotFound) {
		return "", err
	}
	return "", client.ErrNotFound
}

func (r *serviceAccountResource) normalizeEntryManagedBy(ctx context.Context, managers []string) ([]string, error) {
	if len(managers) == 0 {
		return []string{}, nil
	}
	normalized := make([]string, 0, len(managers))
	for _, manager := range managers {
		uuid, err := r.resolveManagerUUID(ctx, manager)
		if err == nil {
			normalized = append(normalized, uuid)
			continue
		}
		if errors.Is(err, client.ErrNotFound) {
			normalized = append(normalized, manager)
			continue
		}
		return nil, err
	}
	return normalized, nil
}

func (r *serviceAccountResource) resolveEntryManagedBySPNs(ctx context.Context, managers []string) ([]string, error) {
	if len(managers) == 0 {
		return []string{}, nil
	}
	resolved := make([]string, 0, len(managers))
	for _, manager := range managers {
		spn, err := r.resolveManagerSPN(ctx, manager)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, spn)
	}
	return resolved, nil
}

func (r *serviceAccountResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	if req.State.Raw.IsNull() {
		return
	}
	var plan, state serviceAccountResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.PosixEnabled.IsNull() || plan.PosixEnabled.IsUnknown() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("posix_enabled"), state.PosixEnabled)...)
	}
	if !state.PosixEnabled.IsNull() && !state.PosixEnabled.IsUnknown() && state.PosixEnabled.ValueBool() {
		if (plan.GIDNumber.IsNull() || plan.GIDNumber.IsUnknown()) && !state.GIDNumber.IsNull() && !state.GIDNumber.IsUnknown() {
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("gidnumber"), state.GIDNumber)...)
		}
		if (plan.Shell.IsNull() || plan.Shell.IsUnknown()) && !state.Shell.IsNull() && !state.Shell.IsUnknown() {
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("shell"), state.Shell)...)
		}
	} else {
		if plan.GIDNumber.IsUnknown() {
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("gidnumber"), types.Int64Null())...)
		}
		if plan.Shell.IsUnknown() {
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("shell"), types.StringNull())...)
		}
	}
	if !plan.EntryManagedBy.IsNull() && !plan.EntryManagedBy.IsUnknown() {
		var managers []string
		resp.Diagnostics.Append(plan.EntryManagedBy.ElementsAs(ctx, &managers, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		normalized, err := r.normalizeEntryManagedBy(ctx, managers)
		if err != nil {
			resp.Diagnostics.AddError("Error Normalizing entry_managed_by", err.Error())
			return
		}
		managedBySet, diags := types.SetValueFrom(ctx, types.StringType, normalized)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("entry_managed_by"), managedBySet)...)
	}
}

func (r *serviceAccountResource) applyServiceAccountState(ctx context.Context, model *serviceAccountResourceModel, sa *client.ServiceAccount) error {
	if sa.UUID == "" {
		return errors.New("Kanidm did not return a UUID for the requested service account")
	}

	model.ID = types.StringValue(sa.UUID)
	model.Name = types.StringValue(sa.Name)
	model.DisplayName = types.StringValue(sa.DisplayName)
	if len(sa.Mail) > 0 {
		mailList, diags := types.ListValueFrom(ctx, types.StringType, sa.Mail)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		model.Mail = mailList
	} else {
		model.Mail = types.ListNull(types.StringType)
	}
	if unixToken, err := r.client.GetAccountUnixToken(ctx, sa.UUID); err == nil {
		model.PosixEnabled = types.BoolValue(true)
		model.GIDNumber = types.Int64Value(unixToken.GIDNumber)
		if unixToken.Shell != "" {
			model.Shell = types.StringValue(unixToken.Shell)
		} else {
			model.Shell = types.StringNull()
		}
	} else if client.UnixTokenUnavailable(err) {
		model.PosixEnabled = types.BoolValue(false)
		model.GIDNumber = types.Int64Null()
		model.Shell = types.StringNull()
	} else {
		return err
	}

	normalizedManagers, err := r.normalizeEntryManagedBy(ctx, sa.EntryManagedBy)
	if err != nil {
		return err
	}
	if len(normalizedManagers) > 0 {
		embySet, diags := types.SetValueFrom(ctx, types.StringType, normalizedManagers)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		model.EntryManagedBy = embySet
	} else {
		model.EntryManagedBy = types.SetNull(types.StringType)
	}
	if sa.ValidFrom != "" {
		model.ValidFrom = types.StringValue(sa.ValidFrom)
	} else {
		model.ValidFrom = types.StringNull()
	}
	if sa.ExpireAt != "" {
		model.ExpireAt = types.StringValue(sa.ExpireAt)
	} else {
		model.ExpireAt = types.StringNull()
	}

	return nil
}

func (r *serviceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceAccountResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := validateServiceAccountTimestamp("valid_from", plan.ValidFrom); err != nil {
		resp.Diagnostics.AddError("Invalid valid_from", err.Error())
		return
	}
	if err := validateServiceAccountTimestamp("expire_at", plan.ExpireAt); err != nil {
		resp.Diagnostics.AddError("Invalid expire_at", err.Error())
		return
	}
	if err := validateServiceAccountPOSIX(plan); err != nil {
		resp.Diagnostics.AddError("Invalid POSIX Configuration", err.Error())
		return
	}

	tflog.Debug(ctx, "Creating service account", map[string]any{
		"name":        plan.Name.ValueString(),
		"displayname": plan.DisplayName.ValueString(),
	})

	// Extract entry_managed_by (required)
	var entryManagedBy []string
	var mail []string
	var err error
	resp.Diagnostics.Append(plan.EntryManagedBy.ElementsAs(ctx, &entryManagedBy, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Mail.IsNull() && !plan.Mail.IsUnknown() {
		resp.Diagnostics.Append(plan.Mail.ElementsAs(ctx, &mail, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	entryManagedBy, err = r.resolveEntryManagedBySPNs(ctx, entryManagedBy)
	if err != nil {
		resp.Diagnostics.AddError("Error Resolving entry_managed_by", err.Error())
		return
	}

	// Create the service account (this also generates an initial API token)
	sa, err := r.client.CreateServiceAccount(ctx, plan.Name.ValueString(), plan.DisplayName.ValueString(), entryManagedBy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Service Account",
			"Could not create service account: "+err.Error(),
		)
		return
	}

	plan.APIToken = types.StringValue(sa.APIToken)
	if !plan.ValidFrom.IsNull() && !plan.ValidFrom.IsUnknown() {
		if err := r.client.SetServiceAccountValidFrom(ctx, sa.Name, plan.ValidFrom.ValueString()); err != nil {
			resp.Diagnostics.AddError("Error Updating Valid From", "Service account was created but valid_from could not be set: "+err.Error())
			return
		}
	}
	if !plan.ExpireAt.IsNull() && !plan.ExpireAt.IsUnknown() {
		if err := r.client.SetServiceAccountExpireAt(ctx, sa.Name, plan.ExpireAt.ValueString()); err != nil {
			resp.Diagnostics.AddError("Error Updating Expire At", "Service account was created but expire_at could not be set: "+err.Error())
			return
		}
	}
	posixEnabled := (!plan.PosixEnabled.IsNull() && !plan.PosixEnabled.IsUnknown() && plan.PosixEnabled.ValueBool()) || (!plan.GIDNumber.IsNull() && !plan.GIDNumber.IsUnknown()) || (!plan.Shell.IsNull() && !plan.Shell.IsUnknown() && plan.Shell.ValueString() != "")
	if posixEnabled {
		var gid *int64
		if !plan.GIDNumber.IsNull() && !plan.GIDNumber.IsUnknown() {
			value := plan.GIDNumber.ValueInt64()
			gid = &value
		}
		var shell *string
		if !plan.Shell.IsNull() && !plan.Shell.IsUnknown() {
			value := plan.Shell.ValueString()
			shell = &value
		}
		if err := r.client.SetServiceAccountUnix(ctx, sa.Name, gid, shell); err != nil {
			resp.Diagnostics.AddError("Error Enabling POSIX Service Account", err.Error())
			return
		}
	}

	createdSA, err := r.client.GetServiceAccount(ctx, sa.Name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Service Account",
			"Service account was created but could not be read back: "+err.Error(),
		)
		return
	}

	if err := r.applyServiceAccountState(ctx, &plan, createdSA); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Service Account",
			"Service account was created but could not be mapped back to Terraform state: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Service account created successfully", map[string]any{
		"id":          plan.ID.ValueString(),
		"displayname": plan.DisplayName.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading service account", map[string]any{
		"id": state.ID.ValueString(),
	})

	// Get current service account from API
	sa, err := r.client.GetServiceAccount(ctx, state.ID.ValueString())
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			tflog.Warn(ctx, "Service account not found, removing from state", map[string]any{
				"id": state.ID.ValueString(),
			})
			resp.State.RemoveResource(ctx)
			return
		}

		resp.Diagnostics.AddError(
			"Error Reading Service Account",
			"Could not read service account: "+err.Error(),
		)
		return
	}

	// Update state with current values
	if err := r.applyServiceAccountState(ctx, &state, sa); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Service Account",
			"Could not map service account data into Terraform state: "+err.Error(),
		)
		return
	}

	// API token is write-only and cannot be read back, preserve existing state value

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state serviceAccountResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := validateServiceAccountPOSIX(plan); err != nil {
		resp.Diagnostics.AddError("Invalid POSIX Configuration", err.Error())
		return
	}

	tflog.Debug(ctx, "Updating service account", map[string]any{
		"id": state.ID.ValueString(),
	})
	var err error
	var mail []string
	currentPosixEnabled := !state.PosixEnabled.IsNull() && !state.PosixEnabled.IsUnknown() && state.PosixEnabled.ValueBool()
	desiredPosixEnabled := (!plan.PosixEnabled.IsNull() && !plan.PosixEnabled.IsUnknown() && plan.PosixEnabled.ValueBool()) || (!plan.GIDNumber.IsNull() && !plan.GIDNumber.IsUnknown()) || (!plan.Shell.IsNull() && !plan.Shell.IsUnknown() && plan.Shell.ValueString() != "")
	if currentPosixEnabled && !desiredPosixEnabled {
		resp.Diagnostics.AddError("Unsupported POSIX Update", "Disabling service account POSIX support is not currently supported by this provider.")
		return
	}
	posixChanged := !plan.PosixEnabled.Equal(state.PosixEnabled) || !plan.GIDNumber.Equal(state.GIDNumber) || !plan.Shell.Equal(state.Shell)

	// Check if entry_managed_by has changed
	var entryManagedBy []string
	entryManagedByChanged := !plan.EntryManagedBy.Equal(state.EntryManagedBy)
	mailChanged := !plan.Mail.Equal(state.Mail)
	if entryManagedByChanged {
		if !plan.EntryManagedBy.IsNull() && !plan.EntryManagedBy.IsUnknown() {
			resp.Diagnostics.Append(plan.EntryManagedBy.ElementsAs(ctx, &entryManagedBy, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			entryManagedBy, err = r.resolveEntryManagedBySPNs(ctx, entryManagedBy)
			if err != nil {
				resp.Diagnostics.AddError("Error Resolving entry_managed_by", err.Error())
				return
			}
		} else {
			entryManagedBy = []string{} // Explicitly clear if set to null
		}

		tflog.Debug(ctx, "EntryManagedBy changed, updating service account", map[string]any{
			"id": state.ID.ValueString(),
		})
	}
	if mailChanged {
		if !plan.Mail.IsNull() && !plan.Mail.IsUnknown() {
			resp.Diagnostics.Append(plan.Mail.ElementsAs(ctx, &mail, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		} else {
			mail = []string{}
		}
	}

	nameChanged := !plan.Name.Equal(state.Name)
	// Check if displayname has changed
	displayNameChanged := !plan.DisplayName.Equal(state.DisplayName)

	// Only call UpdateServiceAccount if something changed
	if nameChanged || displayNameChanged || entryManagedByChanged || mailChanged {
		var name *string
		if nameChanged {
			newName := plan.Name.ValueString()
			name = &newName
		}

		var displayName *string
		if displayNameChanged {
			newDisplayName := plan.DisplayName.ValueString()
			displayName = &newDisplayName
		}

		if displayNameChanged {
			tflog.Debug(ctx, "Displayname changed, updating service account", map[string]any{
				"id":              state.ID.ValueString(),
				"old_displayname": state.DisplayName.ValueString(),
				"new_displayname": plan.DisplayName.ValueString(),
			})
		}

		// Pass nil for entryManagedBy if it hasn't changed
		var emby []string
		if entryManagedByChanged {
			emby = entryManagedBy
		} else {
			emby = nil
		}
		var mailToApply []string
		if mailChanged {
			mailToApply = mail
		} else {
			mailToApply = nil
		}

		err := r.client.UpdateServiceAccount(
			ctx,
			state.ID.ValueString(),
			name,
			displayName,
			emby,
			mailToApply,
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Updating Service Account",
				"Could not update service account: "+err.Error(),
			)
			return
		}
	}
	if !plan.ValidFrom.Equal(state.ValidFrom) {
		if plan.ValidFrom.IsNull() {
			if err := r.client.ClearServiceAccountValidFrom(ctx, state.ID.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error Clearing Valid From", "Could not clear valid_from: "+err.Error())
				return
			}
		} else if !plan.ValidFrom.IsUnknown() {
			if err := r.client.SetServiceAccountValidFrom(ctx, state.ID.ValueString(), plan.ValidFrom.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error Updating Valid From", "Could not update valid_from: "+err.Error())
				return
			}
		}
	}
	if !plan.ExpireAt.Equal(state.ExpireAt) {
		if plan.ExpireAt.IsNull() {
			if err := r.client.ClearServiceAccountExpireAt(ctx, state.ID.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error Clearing Expire At", "Could not clear expire_at: "+err.Error())
				return
			}
		} else if !plan.ExpireAt.IsUnknown() {
			if err := r.client.SetServiceAccountExpireAt(ctx, state.ID.ValueString(), plan.ExpireAt.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error Updating Expire At", "Could not update expire_at: "+err.Error())
				return
			}
		}
	}
	if posixChanged && (desiredPosixEnabled || currentPosixEnabled) {
		var gid *int64
		if !plan.GIDNumber.IsNull() && !plan.GIDNumber.IsUnknown() {
			value := plan.GIDNumber.ValueInt64()
			gid = &value
		}
		var shell *string
		if !plan.Shell.IsNull() && !plan.Shell.IsUnknown() {
			value := plan.Shell.ValueString()
			shell = &value
		}
		if err := r.client.SetServiceAccountUnix(ctx, state.ID.ValueString(), gid, shell); err != nil {
			resp.Diagnostics.AddError("Error Updating POSIX Service Account", err.Error())
			return
		}
	}

	updatedSA, err := r.client.GetServiceAccount(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Service Account",
			"Service account was updated but could not be read back: "+err.Error(),
		)
		return
	}

	if err := r.applyServiceAccountState(ctx, &plan, updatedSA); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Service Account",
			"Service account was updated but could not be mapped back to Terraform state: "+err.Error(),
		)
		return
	}

	// Preserve API token (cannot be updated)
	plan.APIToken = state.APIToken

	tflog.Debug(ctx, "Service account updated successfully", map[string]any{
		"id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting service account", map[string]any{
		"id": state.ID.ValueString(),
	})

	// Delete the service account
	if err := r.client.DeleteServiceAccount(ctx, state.ID.ValueString()); err != nil {
		if errors.Is(err, client.ErrNotFound) {
			tflog.Warn(ctx, "Service account not found during delete, removing from state", map[string]any{
				"id": state.ID.ValueString(),
			})
			return
		}

		resp.Diagnostics.AddError(
			"Error Deleting Service Account",
			"Could not delete service account: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Service account deleted successfully", map[string]any{
		"id": state.ID.ValueString(),
	})
}

func (r *serviceAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the ID directly as the import identifier
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)

	tflog.Debug(ctx, "Imported service account", map[string]any{
		"id": req.ID,
	})

	// Add a warning about the API token
	resp.Diagnostics.AddWarning(
		"API Token Not Available",
		"The API token for this service account is not available after import. "+
			"If you need the token, you must regenerate it manually using the Kanidm CLI or web interface.",
	)
}
