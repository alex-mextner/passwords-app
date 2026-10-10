"""Common base for the package's Apple-protocol exceptions."""


class AppleError(RuntimeError):
    """Base for every error raised against an Apple service or its wire formats."""
