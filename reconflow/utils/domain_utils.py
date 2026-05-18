"""Domain and target normalization utilities."""


def normalize_target(target: str) -> str:
    return target.strip().lower()
