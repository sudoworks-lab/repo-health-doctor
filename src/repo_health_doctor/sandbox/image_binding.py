"""Pure image-identity checks used by execution authorization."""

from __future__ import annotations

import re


_IMAGE_REFERENCE = re.compile(
    r"^[a-z0-9][a-z0-9./:_-]{0,255}@sha256:[0-9a-f]{64}$"
)
_FULL_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


def is_digest_pinned_authorization_reference(value: object) -> bool:
    """Return whether a requested authorization reference is exact and pinned."""

    return isinstance(value, str) and bool(_IMAGE_REFERENCE.fullmatch(value))


def is_safe_docker_image_token(value: object) -> bool:
    """Reject image values that could be parsed as Docker run options."""

    if not isinstance(value, str) or not value or value.startswith("-"):
        return False
    return not any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def is_full_local_image_id(value: object) -> bool:
    """Return whether a value has the full local Docker image ID shape."""

    return isinstance(value, str) and bool(_FULL_IMAGE_ID.fullmatch(value))
