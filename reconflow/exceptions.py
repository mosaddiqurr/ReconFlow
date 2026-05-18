"""Custom exceptions for ReconFlow."""


class ReconFlowError(Exception):
    """Base exception for all custom ReconFlow errors."""


class ConfigurationError(ReconFlowError):
    """Raised when config parsing or validation fails."""
