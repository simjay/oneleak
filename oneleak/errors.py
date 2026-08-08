"""Exception hierarchy. Error messages must never dump raw sensitive content."""


class OneleakError(Exception):
    pass


class ConfigError(OneleakError):
    """Bad rule/config definitions: duplicate IDs, invalid regex, unknown fields."""


class ScanError(OneleakError):
    """Runtime scanning failures (unreadable path, etc.)."""
