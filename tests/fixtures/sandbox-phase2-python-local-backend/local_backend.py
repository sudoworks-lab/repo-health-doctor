from __future__ import annotations


def get_requires_for_build_wheel(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    raise RuntimeError("local backend fixture is for sandbox planning only")
