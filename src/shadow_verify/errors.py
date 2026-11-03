"""User-facing errors. These exit 2; they are not claim verdicts."""


class ShadowVerifyError(Exception):
    """Base error for bad input or a refused call."""


class ClaimsError(ShadowVerifyError):
    """The claims file or an expected block is not valid."""
