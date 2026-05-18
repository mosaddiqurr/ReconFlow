"""Parser stubs for tool output normalization."""


def parse_raw_output(raw_text: str) -> dict:
    """Return a normalized placeholder structure from raw text."""
    return {"status": "placeholder", "raw_length": len(raw_text)}
