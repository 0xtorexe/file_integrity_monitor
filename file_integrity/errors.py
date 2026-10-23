"""Errors that are expected during normal use and should be shown to the user."""


class FimError(Exception):
    """A user-facing error such as a missing directory or invalid baseline."""


class BaselineExistsError(FimError):
    """Raised when a baseline exists and the caller did not ask to overwrite it."""

    def __init__(self, path: object) -> None:
        self.path = path
        super().__init__(f"baseline already exists: {path}")
