from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import typer

from kanidm_tf_import.builtin_groups import ALL_EXTERNAL_MANAGED
from kanidm_tf_import.client import KanidmClient
from kanidm_tf_import.generators.group import generate_group
from kanidm_tf_import.generators.oauth2_client import generate_oauth2_client
from kanidm_tf_import.generators.person import generate_person
from kanidm_tf_import.generators.service_account import generate_service_account
from kanidm_tf_import.hcl import HCLBuilder
from kanidm_tf_import.resolver import Resolver, sanitize_tf_name

_AUTO_GID_RE = re.compile(r"^(\s+)gidnumber(\s*=\s*)(\d+)\s*$", re.MULTILINE)

app = typer.Typer(
    name="kanidm-tf-import",
    help="Generate Terraform HCL configuration from a live Kanidm instance.",
)


def _make_client(url: str, token: str) -> KanidmClient:
    return KanidmClient(url, token)


def _build_versions_tf() -> str:
    return (
        'terraform {\n'
        '  required_version = ">= 1.6.0"\n'
        '\n'
        '  required_providers {\n'
        '    kanidm = {\n'
        '      source = "ssoriche/kanidm"\n'
        '    }\n'
        '  }\n'
        '}\n'
    )


def _build_variables_tf() -> str:
    return (
        'variable "kanidm_url" {\n'
        '  description = "Kanidm server URL"\n'
        '  type        = string\n'
        '}\n'
        '\n'
        'variable "kanidm_token" {\n'
        '  description = "Kanidm API token"\n'
        '  type        = string\n'
        '  sensitive   = true\n'
        '}\n'
    )


IMPORTABLE_RESOURCES = {
    "kanidm_person",
    "kanidm_group",
    "kanidm_service_account",
    "kanidm_oauth2_basic",
    "kanidm_oauth2_public",
}


def _expected_gid(uuid_str: str) -> int:
    raw = uuid_str.replace("-", "")
    last_4_bytes = bytes.fromhex(raw[-8:])
    gid = int.from_bytes(last_4_bytes, "big")
    return (gid & 0x0FFFFFFF) | 0x70000000


def _is_auto_gid(uuid_str: str, gid: int) -> bool:
    return gid == _expected_gid(uuid_str)


def _comment_auto_gids(hcl_text: str, auto_gids: set[int]) -> str:
    if not auto_gids:
        return hcl_text

    def _replace(m: re.Match) -> str:
        gid = int(m.group(3))
        if gid in auto_gids:
            return f"{m.group(1)}# gidnumber{m.group(2)}{gid}  # auto-generated from UUID"
        return m.group(0)

    return _AUTO_GID_RE.sub(_replace, hcl_text)


def _build_import_scripts(
    resources: list[tuple[str, str, str]],
) -> tuple[str, str]:
    sh_lines = ["#!/bin/bash", "# Import all resources into Terraform state", ""]
    ps_lines = ["# Import all resources into Terraform state", ""]

    for resource_type, tf_name, import_id in resources:
        if resource_type in IMPORTABLE_RESOURCES:
            sh_lines.append(f'terraform import {resource_type}.{tf_name} "{import_id}"')
            ps_lines.append(f'terraform import {resource_type}.{tf_name} "{import_id}"')
        else:
            sh_lines.append(f"# {resource_type}.{tf_name} does not support terraform import")
            ps_lines.append(f"# {resource_type}.{tf_name} does not support terraform import")

    sh_lines.append("")
    ps_lines.append("")
    return "\n".join(sh_lines), "\n".join(ps_lines)


@app.command()
def generate(
    url: str = typer.Option(..., "--url", "-u", envvar="KANIDM_URL", help="Kanidm server URL"),
    token: str = typer.Option(
        ..., "--token", "-t", envvar="KANIDM_TOKEN", help="API token"
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir", "-o", help="Output directory (default: stdout)"
    ),
    include_persons: bool = typer.Option(True, "--persons/--no-persons", help="Include persons"),
    include_groups: bool = typer.Option(True, "--groups/--no-groups", help="Include groups"),
    include_service_accounts: bool = typer.Option(
        True, "--service-accounts/--no-service-accounts", help="Include service accounts"
    ),
    include_oauth2: bool = typer.Option(
        True, "--oauth2-clients/--no-oauth2-clients", help="Include OAuth2 clients"
    ),
    with_provider: bool = typer.Option(
        True, "--provider/--no-provider", help="Include provider block"
    ),
    with_import_script: bool = typer.Option(
        True, "--import-script/--no-import-script", help="Generate import.sh"
    ),
) -> None:
    client = _make_client(url, token)

    try:
        resolver = Resolver()

        persons = client.list_persons() if include_persons else []
        groups = client.list_groups() if include_groups else []
        service_accounts = client.list_service_accounts() if include_service_accounts else []
        oauth2_clients = client.list_oauth2_clients() if include_oauth2 else []

        for p in persons:
            resolver.register(
                "kanidm_person",
                sanitize_tf_name(p.name),
                p.uuid,
                p.name,
                p.spn,
            )

        for g in groups:
            tf_name = sanitize_tf_name(g.name)
            resolver.register(
                "kanidm_group",
                tf_name,
                g.uuid,
                g.name,
                g.spn,
            )
            if g.name in ALL_EXTERNAL_MANAGED:
                resolver.register_builtin(tf_name)

        for sa in service_accounts:
            resolver.register(
                "kanidm_service_account",
                sanitize_tf_name(sa.name),
                sa.uuid,
                sa.name,
                sa.spn,
            )

        for o in oauth2_clients:
            resource_type = (
                "kanidm_oauth2_public"
                if o.is_public
                else "kanidm_oauth2_basic"
            )
            resolver.register(
                resource_type,
                sanitize_tf_name(o.name),
                o.uuid,
                o.name,
            )

        resources_builder = HCLBuilder()
        import_resources: list[tuple[str, str, str]] = []
        auto_gids: set[int] = set()

        if include_persons:
            for person in persons:
                posix_info = client.get_account_unix_token(person.name)
                if posix_info and posix_info.get("gidnumber") and person.uuid:
                    if _is_auto_gid(person.uuid, posix_info["gidnumber"]):
                        auto_gids.add(posix_info["gidnumber"])
                tf_name = generate_person(person, client, resolver, resources_builder, posix_info)
                import_resources.append(("kanidm_person", tf_name, person.name))

        if include_groups:
            for group in groups:
                posix_info = client.get_group_unix_token(group.name)
                if posix_info and posix_info.get("gidnumber") and group.uuid:
                    if _is_auto_gid(group.uuid, posix_info["gidnumber"]):
                        auto_gids.add(posix_info["gidnumber"])
                tf_name = generate_group(group, client, resolver, resources_builder, posix_info)
                if tf_name:
                    if group.name in ALL_EXTERNAL_MANAGED:
                        import_resources.append(("kanidm_group_members", tf_name, group.name))
                    else:
                        import_resources.append(("kanidm_group", tf_name, group.name))

        if include_service_accounts:
            for sa in service_accounts:
                posix_info = client.get_account_unix_token(sa.name)
                if posix_info and posix_info.get("gidnumber") and sa.uuid:
                    if _is_auto_gid(sa.uuid, posix_info["gidnumber"]):
                        auto_gids.add(posix_info["gidnumber"])
                tf_name = generate_service_account(sa, client, resolver, resources_builder, posix_info)
                import_resources.append(("kanidm_service_account", tf_name, sa.name))

        if include_oauth2:
            for o in oauth2_clients:
                tf_name = generate_oauth2_client(o, client, resolver, resources_builder)
                resource_type = (
                    "kanidm_oauth2_public"
                    if o.is_public
                    else "kanidm_oauth2_basic"
                )
                import_resources.append((resource_type, tf_name, o.name))

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

            if with_provider:
                (output_dir / "versions.tf").write_text(_build_versions_tf())
                (output_dir / "variables.tf").write_text(_build_variables_tf())

            (output_dir / "resources.tf").write_text(_comment_auto_gids(resources_builder.dumps(), auto_gids))

            if with_import_script:
                sh_script, ps_script = _build_import_scripts(import_resources)
                (output_dir / "import.sh").write_text(sh_script)
                (output_dir / "import.ps1").write_text(ps_script)

            typer.echo(f"Generated files in {output_dir}/")
        else:
            if with_provider:
                print(_build_versions_tf())
                print(_build_variables_tf())

            print(_comment_auto_gids(resources_builder.dumps(), auto_gids))

    finally:
        client.close()


if __name__ == "__main__":
    app()
