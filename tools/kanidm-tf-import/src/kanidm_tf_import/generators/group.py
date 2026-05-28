from __future__ import annotations

from typing import TYPE_CHECKING

from kanidm_tf_import.builtin_groups import ALL_EXTERNAL_MANAGED
from kanidm_tf_import.client import Entry
from kanidm_tf_import.hcl import HCLBuilder, q
from kanidm_tf_import.resolver import sanitize_tf_name

if TYPE_CHECKING:
    from kanidm_tf_import.client import KanidmClient
    from kanidm_tf_import.resolver import Resolver


def _quote_list(values: list[str]) -> list[str]:
    return [q(v) for v in values]


def generate_group(
    group: Entry,
    client: KanidmClient,
    resolver: Resolver,
    builder: HCLBuilder,
    posix_info: dict | None = None,
) -> str | None:
    tf_name = sanitize_tf_name(group.name)
    is_external = group.name in ALL_EXTERNAL_MANAGED

    if is_external:
        return _generate_group_members(group, resolver, builder, tf_name)
    else:
        return _generate_managed_group(group, resolver, builder, tf_name, posix_info)


def _filter_non_builtin_members(
    members: list[str],
    resolver: Resolver,
) -> list[str]:
    resolved = []
    for member in members:
        ref = resolver.resolve_member_ref(member)
        if ref and ref.startswith("kanidm_group."):
            tf_name = ref.split(".")[1]
            if resolver.is_builtin_group(tf_name):
                continue
        resolved.append(ref if ref else member)
    return resolved


def _generate_group_members(
    group: Entry,
    resolver: Resolver,
    builder: HCLBuilder,
    tf_name: str,
) -> str | None:
    if not group.members:
        return None

    non_builtin = _filter_non_builtin_members(group.members, resolver)
    if not non_builtin:
        return None

    builder.resource("kanidm_group_members", tf_name, group=q(group.name), members=non_builtin)
    return tf_name


def _generate_managed_group(
    group: Entry,
    resolver: Resolver,
    builder: HCLBuilder,
    tf_name: str,
    posix_info: dict | None = None,
) -> str:
    attrs: dict = {"name": q(group.name)}

    if group.description:
        attrs["description"] = q(group.description)

    if group.mail:
        attrs["mail"] = _quote_list(group.mail)

    if posix_info and posix_info.get("name"):
        attrs["posix_enabled"] = True
        gidnumber = posix_info.get("gidnumber")
        if gidnumber:
            attrs["gidnumber"] = gidnumber

    if group.entry_managed_by:
        resolved = []
        for mgr in group.entry_managed_by:
            ref = resolver.resolve(mgr)
            resolved.append(ref if ref else mgr)
        attrs["entry_managed_by"] = resolved

    if group.members:
        resolved = []
        for member in group.members:
            ref = resolver.resolve_member_ref(member)
            resolved.append(ref if ref else member)
        attrs["members"] = resolved

    builder.resource("kanidm_group", tf_name, **attrs)
    return tf_name
