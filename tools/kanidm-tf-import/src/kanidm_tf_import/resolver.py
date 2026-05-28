from __future__ import annotations

import re


def sanitize_tf_name(name: str) -> str:
    sanitized = name.replace("-", "_").replace(".", "_").replace("@", "_")
    sanitized = re.sub(r"_+", "_", sanitized)
    sanitized = sanitized.strip("_")
    if sanitized and sanitized[0].isdigit():
        sanitized = f"_{sanitized}"
    return sanitized


class Resolver:
    def __init__(self) -> None:
        self._by_uuid: dict[str, tuple[str, str]] = {}
        self._by_spn: dict[str, tuple[str, str]] = {}
        self._by_name: dict[str, tuple[str, str]] = {}
        self._builtin_tf_names: set[str] = set()

    def register(self, resource_type: str, tf_name: str, uuid: str, name: str, spn: str = "") -> None:
        entry = (resource_type, tf_name)
        if uuid:
            self._by_uuid[uuid] = entry
        if spn:
            self._by_spn[spn] = entry
        if name:
            self._by_name[name] = entry

    def register_builtin(self, tf_name: str) -> None:
        self._builtin_tf_names.add(tf_name)

    def is_builtin_group(self, tf_name: str) -> bool:
        return tf_name in self._builtin_tf_names

    def resolve(self, identifier: str) -> str | None:
        for lookup in (self._by_uuid, self._by_spn, self._by_name):
            if identifier in lookup:
                resource_type, tf_name = lookup[identifier]
                return f"{resource_type}.{tf_name}.id"
        return None

    def resolve_group_ref(self, group_identifier: str) -> str:
        ref = self.resolve(group_identifier)
        if ref and ref.startswith("kanidm_group."):
            return ref
        return group_identifier

    def resolve_member_ref(self, member_identifier: str) -> str:
        ref = self.resolve(member_identifier)
        if ref:
            return ref
        return member_identifier

    def resolve_scope_map_group(self, group_spn: str) -> str:
        group_name = group_spn.split("@")[0] if "@" in group_spn else group_spn
        ref = self.resolve(group_spn) or self.resolve(group_name)
        if ref:
            return ref
        return group_spn
