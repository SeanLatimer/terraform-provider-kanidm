from __future__ import annotations

from typing import TYPE_CHECKING

from kanidm_tf_import.client import Entry
from kanidm_tf_import.hcl import HCLBuilder, q
from kanidm_tf_import.resolver import sanitize_tf_name

if TYPE_CHECKING:
    from kanidm_tf_import.client import KanidmClient
    from kanidm_tf_import.resolver import Resolver


def parse_scope_map(raw: str) -> tuple[str, list[str]]:
    parts = raw.split(":", 1)
    if len(parts) != 2:
        return raw, []
    group = parts[0].strip()
    scopes_part = parts[1].strip().strip("{}")
    scopes = [s.strip().strip('"') for s in scopes_part.split(",") if s.strip().strip('"')]
    return group, scopes


def parse_claim_map(raw: str) -> tuple[str, str, str, list[str]]:
    parts = raw.split(":", 3)
    if len(parts) != 4:
        return raw, "", "array", []
    claim_name = parts[0]
    group = parts[1]
    join_char = parts[2]
    values_part = parts[3].strip('"')

    join_map = {",": "csv", " ": "ssv", ";": "array"}
    join_strategy = join_map.get(join_char, "array")

    values = [v.strip() for v in values_part.split(",") if v.strip()]
    return claim_name, group, join_strategy, values


def generate_oauth2_client(
    oauth2: Entry,
    client: KanidmClient,
    resolver: Resolver,
    builder: HCLBuilder,
) -> str:
    tf_name = sanitize_tf_name(oauth2.name)
    is_public = oauth2.is_public
    resource_type = "kanidm_oauth2_public" if is_public else "kanidm_oauth2_basic"

    attrs: dict = {
        "name": q(oauth2.name),
        "displayname": q(oauth2.displayname),
    }

    if oauth2.origin:
        attrs["origin"] = q(oauth2.origin)

    if oauth2.redirect_uris:
        attrs["redirect_uris"] = [q(u) for u in oauth2.redirect_uris]

    scope_map_data = _build_scope_maps(oauth2.scope_maps, resolver)
    if scope_map_data:
        attrs["scope_map"] = scope_map_data

    sup_scope_map_data = _build_scope_maps(oauth2.sup_scope_maps, resolver)
    if sup_scope_map_data:
        attrs["sup_scope_map"] = sup_scope_map_data

    claim_map_data = _build_claim_maps(oauth2.claim_maps, resolver)
    if claim_map_data:
        attrs["claim_map"] = claim_map_data

    builder.resource(resource_type, tf_name, **attrs)
    return tf_name


def _build_scope_maps(raw_maps: list[str], resolver: Resolver) -> list[dict]:
    result = []
    for raw in raw_maps:
        group, scopes = parse_scope_map(raw)
        group_ref = resolver.resolve_scope_map_group(group)
        result.append({
            "group": group_ref,
            "scopes": [q(s) for s in scopes],
        })
    return result


def _build_claim_maps(raw_maps: list[str], resolver: Resolver) -> list[dict]:
    result = []
    for raw in raw_maps:
        claim_name, group, join_strategy, values = parse_claim_map(raw)
        group_ref = resolver.resolve_scope_map_group(group)
        result.append({
            "name": q(claim_name),
            "group": group_ref,
            "values": [q(v) for v in values],
            "join": q(join_strategy),
        })
    return result
