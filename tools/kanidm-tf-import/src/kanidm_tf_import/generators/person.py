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


def generate_person(
    person: Entry,
    client: KanidmClient,
    resolver: Resolver,
    builder: HCLBuilder,
    posix_info: dict | None = None,
) -> str:
    tf_name = sanitize_tf_name(person.name)
    attrs: dict = {}

    attrs["name"] = q(person.name)
    attrs["displayname"] = q(person.displayname)

    if person.legalname:
        attrs["legalname"] = q(person.legalname)

    if person.mail:
        attrs["mail"] = _quote_list(person.mail)

    if posix_info and posix_info.get("name"):
        attrs["posix_enabled"] = True
        gidnumber = posix_info.get("gidnumber")
        if gidnumber:
            attrs["gidnumber"] = gidnumber
        shell = posix_info.get("shell", "")
        if shell:
            attrs["shell"] = q(shell)

    if person.valid_from:
        attrs["valid_from"] = q(person.valid_from)

    if person.expire_at:
        attrs["expire_at"] = q(person.expire_at)

    builder.resource("kanidm_person", tf_name, **attrs)
    return tf_name
