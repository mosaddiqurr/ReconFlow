"""Base interface for external recon tool wrappers."""

from abc import ABC, abstractmethod


class ToolAdapter(ABC):
    """Abstract base class for tool integrations.

    Real subprocess execution is intentionally not implemented in this scaffold.
    """

    name: str = "unknown"

    @abstractmethod
    def check_available(self) -> bool:
        """Return whether the tool is installed and usable."""

    @abstractmethod
    def build_command(self, target: str) -> list[str]:
        """Return command-line arguments for the target."""
