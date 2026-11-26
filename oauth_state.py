"""Store the bridge's OAuth state encrypted for the current Windows user."""

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

import win32crypt


class OAuthState:
    def __init__(self, path: Path, resource: str):
        self.path = path
        self.resource = resource

    def read(self) -> dict:
        if not self.path.exists():
            return {}
        _, clear = win32crypt.CryptUnprotectData(self.path.read_bytes(), None, None, None, 1)
        data = json.loads(clear)
        if data.get("resource") != self.resource:
            raise ValueError("OAuth state belongs to a different MCP resource.")
        return data

    def write(self, *, clients, access, refresh) -> None:
        data = {"resource": self.resource}
        for name, records in (("clients", clients), ("access", access), ("refresh", refresh)):
            data[name] = {key: value.model_dump(mode="json") for key, value in records.items()}
        encrypted = win32crypt.CryptProtectData(
            json.dumps(data).encode("utf-8"), "Gemini Windows bridge OAuth state", None, None, None, 1,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=self.path.parent, delete=False) as stream:
            stream.write(encrypted)
            filename = Path(stream.name)
        try:
            filename.replace(self.path)
        finally:
            if filename.exists():
                os.unlink(filename)
