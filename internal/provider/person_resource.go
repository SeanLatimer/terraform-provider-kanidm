package provider

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/ssoriche/terraform-provider-kanidm/internal/client"
)

// Ensure the implementation satisfies the required interfaces
var (
	_ resource.Resource                = (*personResource)(nil)
	_ resource.ResourceWithImportState = (*personResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*personResource)(nil)
)

// NewPersonResource creates a new person resource
func NewPersonResource() resource.Resource {
	return &personResource{}
}

// personResource is the resource implementation
type personResource struct {
	client         *client.Client
	personDefaults personManagementDefaults
}

// personResourceModel describes the resource data model
type personResourceModel struct {
	Name                                types.String `tfsdk:"name"`
	ID                                  types.String `tfsdk:"id"`
	DisplayName                         types.String `tfsdk:"displayname"`
	LegalName                           types.String `tfsdk:"legalname"`
	PosixEnabled                        types.Bool   `tfsdk:"posix_enabled"`
	GIDNumber                           types.Int64  `tfsdk:"gidnumber"`
	Shell                               types.String `tfsdk:"shell"`
	ValidFrom                           types.String `tfsdk:"valid_from"`
	ExpireAt                            types.String `tfsdk:"expire_at"`
	NameManagement                      types.String `tfsdk:"name_management"`
	DisplayManagement                   types.String `tfsdk:"display_management"`
	LegalNameManagement                 types.String `tfsdk:"legalname_management"`
	Mail                                types.List   `tfsdk:"mail"`
	Password                            types.String `tfsdk:"password"`
	GenerateInitialCredentialResetToken types.Bool   `tfsdk:"generate_initial_credential_reset_token"`
	InitialCredentialResetToken         types.String `tfsdk:"initial_credential_reset_token"`
	InitialCredentialResetTokenTTL      types.Int64  `tfsdk:"initial_credential_reset_token_ttl"`
}

// Metadata returns the resource type name
func (r *personResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_person"
}

// Schema defines the schema for the resource
func (r *personResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Manages a Kanidm person account.

## Authentication Setup

Kanidm supports two credential setup workflows:

### Password-Based Authentication
Set the ` + "`password`" + ` attribute to create a password-based account:

` + "```hcl" + `
resource "kanidm_person" "example" {
  name        = "jdoe"
  displayname = "John Doe"
  password    = var.initial_password
}
` + "```" + `

### Passkey/Modern Authentication (Recommended)
Set ` + "`generate_initial_credential_reset_token = true`" + ` to generate a one-time onboarding token for credential setup via the Kanidm web UI:

` + "```hcl" + `
resource "kanidm_person" "example" {
  name                          = "jdoe"
  displayname                   = "John Doe"
  generate_initial_credential_reset_token = true
}

output "initial_credential_reset_token" {
  value     = kanidm_person.example.initial_credential_reset_token
  sensitive = true
}
` + "```" + `

The user can then visit the Kanidm web UI with the token to set up passkeys or passwords.`,

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Person username. This can be managed continuously or treated as a create-time default.",
				Required:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Stable Kanidm UUID for this person. This value is computed after creation/import and used to keep the resource linked across external renames.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"displayname": schema.StringAttribute{
				MarkdownDescription: "Display name of the person.",
				Required:            true,
			},
			"name_management": schema.StringAttribute{
				MarkdownDescription: "How Terraform manages `name`. Valid values: `managed`, `initial`.",
				Optional:            true,
			},
			"display_management": schema.StringAttribute{
				MarkdownDescription: "How Terraform manages `displayname`. Valid values: `managed`, `initial`.",
				Optional:            true,
			},
			"legalname": schema.StringAttribute{
				MarkdownDescription: "Legal name of the person. Use `null` to leave it unset or clear it when managed.",
				Optional:            true,
			},
			"legalname_management": schema.StringAttribute{
				MarkdownDescription: "How Terraform manages `legalname`. Valid values: `managed`, `initial`.",
				Optional:            true,
			},
			"posix_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether POSIX support is enabled for the person. Enabling without a gidnumber lets Kanidm generate one automatically. Disabling after enablement is not currently supported.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"gidnumber": schema.Int64Attribute{
				MarkdownDescription: "Optional POSIX gidnumber for the person. Computed after POSIX is enabled, even when Kanidm generates the value.",
				Optional:            true,
				Computed:            true,
			},
			"shell": schema.StringAttribute{
				MarkdownDescription: "Optional login shell for the POSIX-enabled person.",
				Optional:            true,
				Computed:            true,
			},
			"valid_from": schema.StringAttribute{
				MarkdownDescription: "Earliest RFC3339 time when the person can authenticate. Use `null` to leave unset.",
				Optional:            true,
			},
			"expire_at": schema.StringAttribute{
				MarkdownDescription: "RFC3339 time when the person account expires. Use `null` to leave unset.",
				Optional:            true,
			},
			"mail": schema.ListAttribute{
				MarkdownDescription: "Email addresses for the person.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password for the person account. **Note:** This is write-only and will not be stored in state. " +
					"Mutually exclusive with `generate_initial_credential_reset_token`. " +
					"Consider using `lifecycle { ignore_changes = [password] }` if the password is managed externally.",
				Optional:  true,
				Sensitive: true,
			},
			"generate_initial_credential_reset_token": schema.BoolAttribute{
				MarkdownDescription: "Whether to generate a one-time initial credential reset token for onboarding via the web UI. " +
					"Mutually exclusive with `password`. Defaults to `false`.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"initial_credential_reset_token": schema.StringAttribute{
				MarkdownDescription: "The initial credential reset token generated during resource creation when `generate_initial_credential_reset_token` is `true`. " +
					"This token can be used once to set up credentials via the Kanidm web UI. **Computed value only.**",
				Computed:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"initial_credential_reset_token_ttl": schema.Int64Attribute{
				MarkdownDescription: "Time-to-live for the initial credential reset token in seconds. Defaults to 3600 (1 hour). Only used during resource creation.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(3600),
			},
		},
	}
}

// Configure adds the provider configured client to the resource
func (r *personResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := configureResource(req, resp)
	if data == nil {
		return
	}

	r.client = data.client
	r.personDefaults = data.personDefaults
}

func validateLegalName(value types.String) error {
	if !value.IsNull() && !value.IsUnknown() && value.ValueString() == "" {
		return errors.New("legalname cannot be an empty string; use null to leave it unset or clear it")
	}
	return nil
}

func validateRFC3339Optional(attrName string, value types.String) error {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, value.ValueString()); err != nil {
		return errors.New(attrName + " must be a valid RFC3339 timestamp")
	}
	return nil
}

func validatePersonPOSIX(plan personResourceModel) error {
	posixEnabled := (!plan.PosixEnabled.IsNull() && !plan.PosixEnabled.IsUnknown() && plan.PosixEnabled.ValueBool()) || (!plan.GIDNumber.IsNull() && !plan.GIDNumber.IsUnknown()) || (!plan.Shell.IsNull() && !plan.Shell.IsUnknown() && plan.Shell.ValueString() != "")
	if !posixEnabled {
		return nil
	}
	if !plan.PosixEnabled.IsNull() && !plan.PosixEnabled.IsUnknown() && !plan.PosixEnabled.ValueBool() {
		return errors.New("gidnumber and shell require posix_enabled = true")
	}
	return nil
}

func (r *personResource) resolveManagementModes(plan personResourceModel) (string, string, string, bool, bool, bool, error) {
	nameMode, diags := resolveManagementMode(plan.NameManagement, r.personDefaults.Name, "name_management")
	if diags.HasError() {
		return "", "", "", false, false, false, errors.New(diags[0].Summary())
	}

	displayMode, diags := resolveManagementMode(plan.DisplayManagement, r.personDefaults.Display, "display_management")
	if diags.HasError() {
		return "", "", "", false, false, false, errors.New(diags[0].Summary())
	}

	legalNameMode, diags := resolveManagementMode(plan.LegalNameManagement, r.personDefaults.LegalName, "legalname_management")
	if diags.HasError() {
		return "", "", "", false, false, false, errors.New(diags[0].Summary())
	}

	return nameMode, displayMode, legalNameMode, nameMode == managementModeManaged, displayMode == managementModeManaged, legalNameMode == managementModeManaged, nil
}

func (r *personResource) applyPersonState(ctx context.Context, model *personResourceModel, person *client.Person) error {
	model.ID = types.StringValue(person.UUID)
	model.Name = types.StringValue(person.Name)
	model.DisplayName = types.StringValue(person.DisplayName)
	if person.LegalName != "" {
		model.LegalName = types.StringValue(person.LegalName)
	} else {
		model.LegalName = types.StringNull()
	}
	if unixToken, err := r.client.GetAccountUnixToken(ctx, person.UUID); err == nil {
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
	if person.ValidFrom != "" {
		model.ValidFrom = types.StringValue(person.ValidFrom)
	} else {
		model.ValidFrom = types.StringNull()
	}
	if person.ExpireAt != "" {
		model.ExpireAt = types.StringValue(person.ExpireAt)
	} else {
		model.ExpireAt = types.StringNull()
	}

	if len(person.Mail) > 0 {
		mailList, diags := types.ListValueFrom(ctx, types.StringType, person.Mail)
		if diags.HasError() {
			return errors.New(diags.Errors()[0].Summary())
		}
		model.Mail = mailList
	} else {
		model.Mail = types.ListNull(types.StringType)
	}

	return nil
}

// ModifyPlan suppresses diffs for create-time-only attributes.
func (r *personResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state personResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	nameMode, diags := resolveManagementMode(plan.NameManagement, r.personDefaults.Name, "name_management")
	resp.Diagnostics.Append(diags...)
	displayMode, diags := resolveManagementMode(plan.DisplayManagement, r.personDefaults.Display, "display_management")
	resp.Diagnostics.Append(diags...)
	legalNameMode, diags := resolveManagementMode(plan.LegalNameManagement, r.personDefaults.LegalName, "legalname_management")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if nameMode == managementModeInitial && !state.Name.IsNull() && !state.Name.IsUnknown() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("name"), state.Name)...)
	}

	if displayMode == managementModeInitial && !state.DisplayName.IsNull() && !state.DisplayName.IsUnknown() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("displayname"), state.DisplayName)...)
	}

	if legalNameMode == managementModeInitial && !state.LegalName.IsNull() && !state.LegalName.IsUnknown() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("legalname"), state.LegalName)...)
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

	if !state.GenerateInitialCredentialResetToken.IsNull() && !state.GenerateInitialCredentialResetToken.IsUnknown() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("generate_initial_credential_reset_token"), state.GenerateInitialCredentialResetToken)...)
	}

	if !state.InitialCredentialResetTokenTTL.IsNull() && !state.InitialCredentialResetTokenTTL.IsUnknown() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("initial_credential_reset_token_ttl"), state.InitialCredentialResetTokenTTL)...)
	}
}

// Create creates the resource and sets the initial Terraform state
func (r *personResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan personResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate mutually exclusive options
	hasPassword := !plan.Password.IsNull() && !plan.Password.IsUnknown()
	generateToken := r.personDefaults.GenerateInitialResetToken
	if !plan.GenerateInitialCredentialResetToken.IsNull() && !plan.GenerateInitialCredentialResetToken.IsUnknown() {
		generateToken = plan.GenerateInitialCredentialResetToken.ValueBool()
	}
	tokenTTL := r.personDefaults.InitialResetTokenTTLSeconds
	if !plan.InitialCredentialResetTokenTTL.IsNull() && !plan.InitialCredentialResetTokenTTL.IsUnknown() {
		tokenTTL = plan.InitialCredentialResetTokenTTL.ValueInt64()
	}

	if hasPassword && generateToken {
		resp.Diagnostics.AddError(
			"Conflicting Configuration",
			"Cannot specify both 'password' and 'generate_initial_credential_reset_token'. Choose one authentication setup method.",
		)
		return
	}

	if err := validateLegalName(plan.LegalName); err != nil {
		resp.Diagnostics.AddError("Invalid legalname", err.Error())
		return
	}
	if err := validateRFC3339Optional("valid_from", plan.ValidFrom); err != nil {
		resp.Diagnostics.AddError("Invalid valid_from", err.Error())
		return
	}
	if err := validateRFC3339Optional("expire_at", plan.ExpireAt); err != nil {
		resp.Diagnostics.AddError("Invalid expire_at", err.Error())
		return
	}
	if err := validatePersonPOSIX(plan); err != nil {
		resp.Diagnostics.AddError("Invalid POSIX Configuration", err.Error())
		return
	}

	if _, _, _, _, _, _, err := r.resolveManagementModes(plan); err != nil {
		resp.Diagnostics.AddError(
			"Invalid person management mode",
			err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Creating person", map[string]any{
		"name": plan.Name.ValueString(),
	})

	// Create the person account
	person, err := r.client.CreatePerson(ctx, plan.Name.ValueString(), plan.DisplayName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Person",
			"Could not create person: "+err.Error(),
		)
		return
	}

	// Set password if provided
	if hasPassword {
		tflog.Debug(ctx, "Setting initial password for person")
		if err := r.client.SetPersonPassword(ctx, person.Name, plan.Password.ValueString()); err != nil {
			resp.Diagnostics.AddError(
				"Error Setting Password",
				"Person was created but password could not be set: "+err.Error(),
			)
			return
		}
	}

	// Generate credential reset token if requested
	if generateToken {
		tflog.Debug(ctx, "Generating credential reset token for person")
		ttl := int(tokenTTL)
		token, err := r.client.CreatePersonCredentialResetToken(ctx, person.Name, &ttl)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Generating Credential Reset Token",
				"Person was created but credential reset token could not be generated: "+err.Error(),
			)
			return
		}
		plan.InitialCredentialResetToken = types.StringValue(token)
	}

	// Update mail if provided
	if !plan.Mail.IsNull() && !plan.Mail.IsUnknown() {
		var mailAddrs []string
		resp.Diagnostics.Append(plan.Mail.ElementsAs(ctx, &mailAddrs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if len(mailAddrs) > 0 {
			tflog.Debug(ctx, "Updating mail addresses for person")
			if err := r.client.UpdatePerson(ctx, person.Name, nil, nil, mailAddrs); err != nil {
				resp.Diagnostics.AddError(
					"Error Updating Mail",
					"Person was created but mail addresses could not be set: "+err.Error(),
				)
				return
			}
		}
	}

	if !plan.LegalName.IsNull() && !plan.LegalName.IsUnknown() {
		if err := r.client.SetPersonLegalName(ctx, person.Name, plan.LegalName.ValueString()); err != nil {
			resp.Diagnostics.AddError(
				"Error Updating Legal Name",
				"Person was created but legal name could not be set: "+err.Error(),
			)
			return
		}
	}
	if !plan.ValidFrom.IsNull() && !plan.ValidFrom.IsUnknown() {
		if err := r.client.SetPersonValidFrom(ctx, person.Name, plan.ValidFrom.ValueString()); err != nil {
			resp.Diagnostics.AddError(
				"Error Updating Valid From",
				"Person was created but valid_from could not be set: "+err.Error(),
			)
			return
		}
	}
	if !plan.ExpireAt.IsNull() && !plan.ExpireAt.IsUnknown() {
		if err := r.client.SetPersonExpireAt(ctx, person.Name, plan.ExpireAt.ValueString()); err != nil {
			resp.Diagnostics.AddError(
				"Error Updating Expire At",
				"Person was created but expire_at could not be set: "+err.Error(),
			)
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
		if err := r.client.SetPersonUnix(ctx, person.Name, gid, shell); err != nil {
			resp.Diagnostics.AddError("Error Enabling POSIX Person", err.Error())
			return
		}
	}

	// Read back the person to get the current state
	createdPerson, err := r.client.GetPerson(ctx, person.Name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Person was created but could not be read back: "+err.Error(),
		)
		return
	}

	if createdPerson.UUID == "" {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Person was created but the Kanidm response did not include a UUID.",
		)
		return
	}

	if err := r.applyPersonState(ctx, &plan, createdPerson); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Person was created but could not be mapped back to Terraform state: "+err.Error(),
		)
		return
	}

	// Password is write-only, keep the planned value but don't try to read it back

	// Ensure initial credential reset token fields are properly set with defaults if not already set.
	if plan.GenerateInitialCredentialResetToken.IsNull() || plan.GenerateInitialCredentialResetToken.IsUnknown() {
		plan.GenerateInitialCredentialResetToken = types.BoolValue(generateToken)
	}
	if plan.InitialCredentialResetTokenTTL.IsNull() || plan.InitialCredentialResetTokenTTL.IsUnknown() {
		plan.InitialCredentialResetTokenTTL = types.Int64Value(tokenTTL)
	}
	// If the initial token wasn't generated, ensure it's null not unknown.
	if plan.InitialCredentialResetToken.IsUnknown() {
		plan.InitialCredentialResetToken = types.StringNull()
	}

	tflog.Debug(ctx, "Person created successfully", map[string]any{
		"id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data
func (r *personResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state personResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading person", map[string]any{
		"id": state.ID.ValueString(),
	})

	// Get current person from API
	person, err := r.client.GetPerson(ctx, state.ID.ValueString())
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			tflog.Warn(ctx, "Person not found, removing from state", map[string]any{
				"id": state.ID.ValueString(),
			})
			resp.State.RemoveResource(ctx)
			return
		}

		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Could not read person: "+err.Error(),
		)
		return
	}

	if person.UUID == "" {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Kanidm did not return a UUID for the requested person.",
		)
		return
	}

	if err := r.applyPersonState(ctx, &state, person); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Could not map person data into Terraform state: "+err.Error(),
		)
		return
	}

	// Password is write-only and not readable from API, preserve existing state value
	// Initial credential reset token fields should use defaults when not explicitly set.
	if state.GenerateInitialCredentialResetToken.IsNull() || state.GenerateInitialCredentialResetToken.IsUnknown() {
		state.GenerateInitialCredentialResetToken = types.BoolValue(r.personDefaults.GenerateInitialResetToken)
	}
	if state.InitialCredentialResetTokenTTL.IsNull() || state.InitialCredentialResetTokenTTL.IsUnknown() {
		state.InitialCredentialResetTokenTTL = types.Int64Value(r.personDefaults.InitialResetTokenTTLSeconds)
	}
	// The initial reset token is only set during Create when generated, otherwise null.
	if state.InitialCredentialResetToken.IsUnknown() {
		state.InitialCredentialResetToken = types.StringNull()
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state
func (r *personResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state personResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating person", map[string]any{
		"id": state.ID.ValueString(),
	})

	if err := validateLegalName(plan.LegalName); err != nil {
		resp.Diagnostics.AddError("Invalid legalname", err.Error())
		return
	}
	if err := validateRFC3339Optional("valid_from", plan.ValidFrom); err != nil {
		resp.Diagnostics.AddError("Invalid valid_from", err.Error())
		return
	}
	if err := validateRFC3339Optional("expire_at", plan.ExpireAt); err != nil {
		resp.Diagnostics.AddError("Invalid expire_at", err.Error())
		return
	}
	if err := validatePersonPOSIX(plan); err != nil {
		resp.Diagnostics.AddError("Invalid POSIX Configuration", err.Error())
		return
	}
	currentPosixEnabled := !state.PosixEnabled.IsNull() && !state.PosixEnabled.IsUnknown() && state.PosixEnabled.ValueBool()
	desiredPosixEnabled := (!plan.PosixEnabled.IsNull() && !plan.PosixEnabled.IsUnknown() && plan.PosixEnabled.ValueBool()) || (!plan.GIDNumber.IsNull() && !plan.GIDNumber.IsUnknown()) || (!plan.Shell.IsNull() && !plan.Shell.IsUnknown() && plan.Shell.ValueString() != "")
	if currentPosixEnabled && !desiredPosixEnabled {
		resp.Diagnostics.AddError("Unsupported POSIX Update", "Disabling person POSIX support is not currently supported by this provider.")
		return
	}
	posixChanged := !plan.PosixEnabled.Equal(state.PosixEnabled) || !plan.GIDNumber.Equal(state.GIDNumber) || !plan.Shell.Equal(state.Shell)

	_, _, legalNameMode, manageName, manageDisplay, manageLegalName, err := r.resolveManagementModes(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid person management mode",
			err.Error(),
		)
		return
	}

	// Prepare mail addresses
	var mailAddrs []string
	updateMail := !plan.Mail.IsNull() && !plan.Mail.IsUnknown()
	if !plan.Mail.IsNull() && !plan.Mail.IsUnknown() {
		resp.Diagnostics.Append(plan.Mail.ElementsAs(ctx, &mailAddrs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	var nameValue *string
	if manageName {
		name := plan.Name.ValueString()
		nameValue = &name
	}

	var displayValue *string
	if manageDisplay {
		display := plan.DisplayName.ValueString()
		displayValue = &display
	}

	if nameValue != nil || displayValue != nil || updateMail {
		// Update person attributes using the stable UUID-backed resource ID.
		if err := r.client.UpdatePerson(ctx, state.ID.ValueString(), nameValue, displayValue, mailAddrs); err != nil {
			resp.Diagnostics.AddError(
				"Error Updating Person",
				"Could not update person: "+err.Error(),
			)
			return
		}
	}

	if manageLegalName || (legalNameMode == managementModeInitial && state.LegalName.IsNull() && !plan.LegalName.IsNull() && !plan.LegalName.IsUnknown()) {
		if plan.LegalName.IsNull() {
			if err := r.client.ClearPersonLegalName(ctx, state.ID.ValueString()); err != nil {
				resp.Diagnostics.AddError(
					"Error Clearing Legal Name",
					"Could not clear legal name: "+err.Error(),
				)
				return
			}
		} else if !plan.LegalName.IsUnknown() && !plan.LegalName.Equal(state.LegalName) {
			if err := r.client.SetPersonLegalName(ctx, state.ID.ValueString(), plan.LegalName.ValueString()); err != nil {
				resp.Diagnostics.AddError(
					"Error Updating Legal Name",
					"Could not update legal name: "+err.Error(),
				)
				return
			}
		}
	}

	if !plan.ValidFrom.Equal(state.ValidFrom) {
		if plan.ValidFrom.IsNull() {
			if err := r.client.ClearPersonValidFrom(ctx, state.ID.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error Clearing Valid From", "Could not clear valid_from: "+err.Error())
				return
			}
		} else if !plan.ValidFrom.IsUnknown() {
			if err := r.client.SetPersonValidFrom(ctx, state.ID.ValueString(), plan.ValidFrom.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error Updating Valid From", "Could not update valid_from: "+err.Error())
				return
			}
		}
	}
	if !plan.ExpireAt.Equal(state.ExpireAt) {
		if plan.ExpireAt.IsNull() {
			if err := r.client.ClearPersonExpireAt(ctx, state.ID.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error Clearing Expire At", "Could not clear expire_at: "+err.Error())
				return
			}
		} else if !plan.ExpireAt.IsUnknown() {
			if err := r.client.SetPersonExpireAt(ctx, state.ID.ValueString(), plan.ExpireAt.ValueString()); err != nil {
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
		if err := r.client.SetPersonUnix(ctx, state.ID.ValueString(), gid, shell); err != nil {
			resp.Diagnostics.AddError("Error Updating POSIX Person", err.Error())
			return
		}
	}

	// Update password if changed
	if !plan.Password.Equal(state.Password) && !plan.Password.IsNull() {
		tflog.Debug(ctx, "Updating password for person")
		if err := r.client.SetPersonPassword(ctx, state.ID.ValueString(), plan.Password.ValueString()); err != nil {
			resp.Diagnostics.AddError(
				"Error Updating Password",
				"Person was updated but password could not be changed: "+err.Error(),
			)
			return
		}
	}

	// Read back the updated person
	updatedPerson, err := r.client.GetPerson(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Person was updated but could not be read back: "+err.Error(),
		)
		return
	}

	if updatedPerson.UUID == "" {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Person was updated but the Kanidm response did not include a UUID.",
		)
		return
	}

	if err := r.applyPersonState(ctx, &plan, updatedPerson); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Person",
			"Person was updated but could not be mapped back to Terraform state: "+err.Error(),
		)
		return
	}

	// Ensure initial credential reset token fields are properly set.
	if plan.GenerateInitialCredentialResetToken.IsNull() || plan.GenerateInitialCredentialResetToken.IsUnknown() {
		plan.GenerateInitialCredentialResetToken = state.GenerateInitialCredentialResetToken
	}
	if plan.InitialCredentialResetTokenTTL.IsNull() || plan.InitialCredentialResetTokenTTL.IsUnknown() {
		plan.InitialCredentialResetTokenTTL = state.InitialCredentialResetTokenTTL
	}
	plan.InitialCredentialResetToken = state.InitialCredentialResetToken
	if plan.InitialCredentialResetToken.IsUnknown() {
		plan.InitialCredentialResetToken = types.StringNull()
	}

	tflog.Debug(ctx, "Person updated successfully", map[string]any{
		"id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state
func (r *personResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state personResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting person", map[string]any{
		"id": state.ID.ValueString(),
	})

	// Delete the person
	if err := r.client.DeletePerson(ctx, state.ID.ValueString()); err != nil {
		if errors.Is(err, client.ErrNotFound) {
			// Person already deleted, just remove from state
			tflog.Warn(ctx, "Person not found during delete, removing from state", map[string]any{
				"id": state.ID.ValueString(),
			})
			return
		}

		resp.Diagnostics.AddError(
			"Error Deleting Person",
			"Could not delete person: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Person deleted successfully", map[string]any{
		"id": state.ID.ValueString(),
	})
}

// ImportState imports an existing person into Terraform state
func (r *personResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the ID (username) directly as the import identifier
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)

	tflog.Debug(ctx, "Imported person", map[string]any{
		"id": req.ID,
	})
}
