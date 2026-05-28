package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/ssoriche/terraform-provider-kanidm/internal/client"
)

var (
	_ resource.Resource                = (*systemDeniedNamesResource)(nil)
	_ resource.ResourceWithImportState = (*systemDeniedNamesResource)(nil)
)

func NewSystemDeniedNamesResource() resource.Resource {
	return &systemDeniedNamesResource{}
}

type systemDeniedNamesResource struct {
	client *client.Client
}

type systemDeniedNamesResourceModel struct {
	ID    types.String `tfsdk:"id"`
	Names types.Set    `tfsdk:"names"`
}

func (r *systemDeniedNamesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_system_denied_names"
}

func (r *systemDeniedNamesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Manages the system-wide list of denied user names.

Users in Kanidm can change their name at any time. This resource maintains a list of names that are not allowed to be used, preventing conflicts with system accounts or excluding abusive terms.

This is a singleton resource — only one ` + "`kanidm_system_denied_names`" + ` resource should exist in your configuration.

## Example Usage

` + "```hcl" + `
resource "kanidm_system_denied_names" "this" {
  names = [
    "administrator",
    "superuser",
    "system",
    "guest",
  ]
}
` + "```" + ``,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"names": schema.SetAttribute{
				MarkdownDescription: "Set of denied names. Names in this list cannot be used as Kanidm account names.",
				Required:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (r *systemDeniedNamesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := configureResource(req, resp)
	if data == nil {
		return
	}
	r.client = data.client
}

func (r *systemDeniedNamesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan systemDeniedNamesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var names []string
	resp.Diagnostics.Append(plan.Names.ElementsAs(ctx, &names, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Setting system denied names", map[string]any{
		"count": len(names),
	})

	if err := r.client.AddSystemAttr(ctx, "denied_name", names); err != nil {
		resp.Diagnostics.AddError(
			"Error Setting Denied Names",
			"Could not set system denied names: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue("system")

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *systemDeniedNamesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state systemDeniedNamesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading system denied names")

	names, err := r.client.GetSystemAttr(ctx, "denied_name")
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading Denied Names", err.Error())
		return
	}

	state.ID = types.StringValue("system")
	if len(names) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	namesSet, diags := types.SetValueFrom(ctx, types.StringType, names)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	state.Names = namesSet

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *systemDeniedNamesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state systemDeniedNamesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var desiredNames []string
	resp.Diagnostics.Append(plan.Names.ElementsAs(ctx, &desiredNames, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var currentNames []string
	resp.Diagnostics.Append(state.Names.ElementsAs(ctx, &currentNames, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	toAdd := stringSetDiff(desiredNames, currentNames)
	toRemove := stringSetDiff(currentNames, desiredNames)

	if len(toAdd) > 0 {
		tflog.Debug(ctx, "Appending system denied names", map[string]any{
			"count": len(toAdd),
		})
		if err := r.client.AddSystemAttr(ctx, "denied_name", toAdd); err != nil {
			resp.Diagnostics.AddError(
				"Error Appending Denied Names",
				"Could not append system denied names: "+err.Error(),
			)
			return
		}
	}

	if len(toRemove) > 0 {
		tflog.Debug(ctx, "Removing system denied names", map[string]any{
			"count": len(toRemove),
		})
		if err := r.client.RemoveSystemAttr(ctx, "denied_name", toRemove); err != nil {
			resp.Diagnostics.AddError(
				"Error Removing Denied Names",
				"Could not remove system denied names: "+err.Error(),
			)
			return
		}
	}

	plan.ID = types.StringValue("system")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *systemDeniedNamesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state systemDeniedNamesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var names []string
	resp.Diagnostics.Append(state.Names.ElementsAs(ctx, &names, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(names) > 0 {
		tflog.Debug(ctx, "Removing system denied names", map[string]any{
			"count": len(names),
		})
		if err := r.client.RemoveSystemAttr(ctx, "denied_name", names); err != nil {
			if !errors.Is(err, client.ErrNotFound) {
				resp.Diagnostics.AddError(
					"Error Clearing Denied Names",
					"Could not clear system denied names: "+err.Error(),
				)
				return
			}
		}
	}

	tflog.Debug(ctx, "System denied names cleared")
}

func (r *systemDeniedNamesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Debug(ctx, "Importing system denied names")

	names, err := r.client.GetSystemAttr(ctx, "denied_name")
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			resp.Diagnostics.AddError(
				"Error Importing Denied Names",
				"No denied names found on the system.",
			)
			return
		}
		resp.Diagnostics.AddError("Error Reading Denied Names", err.Error())
		return
	}

	state := systemDeniedNamesResourceModel{
		ID: types.StringValue("system"),
	}

	if len(names) == 0 {
		resp.Diagnostics.AddError(
			"Error Importing Denied Names",
			"No denied names found on the system.",
		)
		return
	}

	namesSet, diags := types.SetValueFrom(ctx, types.StringType, names)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	state.Names = namesSet

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
