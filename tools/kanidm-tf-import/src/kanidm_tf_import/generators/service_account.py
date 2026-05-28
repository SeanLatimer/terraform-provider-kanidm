from __future__ import annotations

from typing import TYPE_CHECKING

from kanidm_tf_import.client import Entry
from kanidm_tf_import.hcl import HCLBuilder, q
from kanidm_tf_import.resolver import sanitize_tf_name

if TYPE_CHECKING:
    from kanidm_tf_import.client import KanidmClient
    from kanidm_tf_import.resolver import Resolver


def _quote_list(values: list[str]) -> list[str]:
    return [q(v) for v in values]


def generate_service_account(
    sa: Entry,
    client: KanidmClient,
    resolver: Resolver,
    builder: HCLBuilder,
    posix_info: dict | None = None,
) -> str:
    tf_name = sanitize_tf_name(sa.name)
    attrs: dict = {}

    attrs["name"] = q(sa.name)

    if sa.displayname:
        attrs["displayname"] = q(sa.displayname)

    if sa.mail:
        attrs["mail"] = _quote_list(sa.mail)

    if posix_info and posix_info.get("name"):
        attrs["posix_enabled"] = True
        gidnumber = posix_info.get("gidnumber")
        if gidnumber:
            attrs["gidnumber"] = gidnumber
        shell = posix_info.get("shell", "")
        if shell:
            attrs["shell"] = q(shell)

    if sa.entry_managed_by:
        resolved = []
        for mgr in sa.entry_managed_by:
            ref = resolver.resolve(mgr)
            resolved.append(ref if ref else mgr)
        attrs["entry_managed_by"] = resolved

    if sa.valid_from:
        attrs["valid_from"] = q(sa.valid_from)

    if sa.expire_at:
        attrs["expire_at"] = q(sa.expire_at)

    builder.resource("kanidm_service_account", tf_name, **attrs)
    return tf_name
