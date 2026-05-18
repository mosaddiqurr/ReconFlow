"""Output formatting helpers."""

from rich.console import Console

console = Console()


def info(message: str) -> None:
    console.print(f"[cyan]{message}[/cyan]")
