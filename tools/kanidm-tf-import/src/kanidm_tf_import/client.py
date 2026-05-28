from __future__ import annotations

import httpx


class KanidmClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=30.0,
            verify=False,
        )

    def _get(self, path: str) -> dict | list:
        resp = self._client.get(path)
        resp.raise_for_status()
        return resp.json()

    def _get_raw(self, path: str) -> str:
        resp = self._client.get(path)
        resp.raise_for_status()
        return resp.text

    def list_persons(self) -> list[Entry]:
        data = self._get("/v1/person")
        return [Entry(raw) for raw in data]

    def get_person(self, id_or_name: str) -> Entry:
        data = self._get(f"/v1/person/{id_or_name}")
        return Entry(data)

    def list_groups(self) -> list[Entry]:
        data = self._get("/v1/group")
        return [Entry(raw) for raw in data]

    def get_group(self, id_or_name: str) -> Entry:
        data = self._get(f"/v1/group/{id_or_name}")
        return Entry(data)

    def get_group_unix_token(self, id_or_name: str) -> dict | None:
        try:
            return self._get(f"/v1/group/{id_or_name}/_unix/_token")
        except httpx.HTTPStatusError as e:
            if e.response.status_code >= 400:
                return None
            raise

    def list_service_accounts(self) -> list[Entry]:
        data = self._get("/v1/service_account")
        return [Entry(raw) for raw in data]

    def get_service_account(self, id_or_name: str) -> Entry:
        data = self._get(f"/v1/service_account/{id_or_name}")
        return Entry(data)

    def get_account_unix_token(self, id_or_name: str) -> dict | None:
        try:
            return self._get(f"/v1/account/{id_or_name}/_unix/_token")
        except httpx.HTTPStatusError as e:
            if e.response.status_code >= 400:
                return None
            raise

    def list_oauth2_clients(self) -> list[Entry]:
        data = self._get("/v1/oauth2")
        return [Entry(raw) for raw in data]

    def get_oauth2_client(self, name: str) -> Entry:
        data = self._get(f"/v1/oauth2/{name}")
        return Entry(data)

    def get_oauth2_basic_secret(self, name: str) -> str | None:
        try:
            return self._get_raw(f"/v1/oauth2/{name}/_basic_secret")
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (404, 403):
                return None
            raise

    def close(self) -> None:
        self._client.close()


class Entry:
    def __init__(self, data: dict) -> None:
        self.attrs: dict = data.get("attrs", data)

    def _first(self, key: str) -> str:
        val = self.attrs.get(key)
        if val is None:
            return ""
        if isinstance(val, list) and len(val) > 0:
            return str(val[0])
        if isinstance(val, str):
            return val
        return ""

    def get_string(self, key: str) -> str:
        return self._first(key)

    def get_string_slice(self, key: str) -> list[str]:
        val = self.attrs.get(key)
        if val is None:
            return []
        if isinstance(val, list):
            return [str(v) for v in val]
        if isinstance(val, str):
            return [val]
        return []

    def get_int(self, key: str) -> int | None:
        val = self._first(key)
        if not val:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    def has_key(self, key: str) -> bool:
        return key in self.attrs

    @property
    def uuid(self) -> str:
        return self.get_string("entryuuid") or self.get_string("uuid")

    @property
    def name(self) -> str:
        return self.get_string("name")

    @property
    def spn(self) -> str:
        return self.get_string("spn")

    @property
    def displayname(self) -> str:
        return self.get_string("displayname")

    @property
    def legalname(self) -> str:
        return self.get_string("legalname")

    @property
    def mail(self) -> list[str]:
        return self.get_string_slice("mail")

    @property
    def description(self) -> str:
        return self.get_string("description")

    @property
    def members(self) -> list[str]:
        return self.get_string_slice("member")

    @property
    def entry_managed_by(self) -> list[str]:
        return self.get_string_slice("entry_managed_by")

    @property
    def redirect_uris(self) -> list[str]:
        return self.get_string_slice("oauth2_rs_origin_landing")

    @property
    def origin(self) -> str:
        o = self.get_string("oauth2_rs_origin")
        if o.endswith("/"):
            o = o[:-1]
        return o

    @property
    def is_public(self) -> bool:
        return not self.has_key("oauth2_rs_basic_secret")

    @property
    def scope_maps(self) -> list[str]:
        return self.get_string_slice("oauth2_rs_scope_map")

    @property
    def sup_scope_maps(self) -> list[str]:
        return self.get_string_slice("oauth2_rs_sup_scope_map")

    @property
    def claim_maps(self) -> list[str]:
        return self.get_string_slice("oauth2_rs_claim_map")

    @property
    def gidnumber(self) -> int | None:
        return self.get_int("gidnumber")

    @property
    def shell(self) -> str:
        return self.get_string("shell")

    @property
    def valid_from(self) -> str:
        return self.get_string("account_valid_from")

    @property
    def expire_at(self) -> str:
        return self.get_string("account_expire")
