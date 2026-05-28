from __future__ import annotations

from typing import Any

import hcl2


def q(value: str) -> str:
    return f'"{value}"'


def ref(address: str) -> str:
    return address


class HCLBuilder:
    def __init__(self) -> None:
        self._doc = hcl2.Builder()

    def resource(
        self, resource_type: str, tf_name: str, **attrs: Any
    ) -> HCLBlockBuilder:
        labels = [q(resource_type), q(tf_name)]
        child = self._doc.block("resource", labels=labels, **attrs)
        return HCLBlockBuilder(child)

    def output(self, name: str, value: str, sensitive: bool = False) -> None:
        self._doc.block("output", labels=[q(name)], value=value, sensitive=sensitive)

    def provider(self, name: str, **attrs: Any) -> None:
        self._doc.block("provider", labels=[q(name)], **attrs)

    def build(self) -> dict:
        return self._doc.build()

    def dumps(self) -> str:
        return hcl2.dumps(self.build())


class HCLBlockBuilder:
    def __init__(self, inner: hcl2.Builder) -> None:
        self._inner = inner

    def block(self, block_type: str, **attrs: Any) -> HCLBlockBuilder:
        child = self._inner.block(block_type, **attrs)
        return HCLBlockBuilder(child)


def string_attrs(**kwargs: str | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in kwargs.items():
        if value is not None and value != "":
            result[key] = q(value)
    return result


def int_attrs(**kwargs: int | None) -> dict[str, int]:
    result: dict[str, int] = {}
    for key, value in kwargs.items():
        if value is not None:
            result[key] = value
    return result


def bool_attrs(**kwargs: bool | None) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for key, value in kwargs.items():
        if value is not None:
            result[key] = value
    return result
