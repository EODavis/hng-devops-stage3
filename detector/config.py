# config.py — Central config loader
# All modules import get_config() instead of reading YAML directly.

import os
import yaml
from pathlib import Path

_config = None  # Module-level singleton


def get_config(path: str = "/app/config.yaml") -> dict:
    """
    Load and return the config dict.
    Injects SLACK_WEBHOOK_URL from environment if not set in yaml.
    Caches after first load — safe to call repeatedly.
    """
    global _config

    if _config is not None:
        return _config

    config_path = Path(path)
    if not config_path.exists():
        # Fallback for local dev
        config_path = Path(__file__).parent / "config.yaml"

    with open(config_path, "r", encoding="utf-8") as f:
        _config = yaml.safe_load(f)

    # Inject Slack webhook from environment variable
    # Environment always wins over config file value
    env_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if env_webhook:
        _config["slack"]["webhook_url"] = env_webhook

    return _config


def get(key_path: str, default=None):
    """
    Dot-notation access to nested config values.
    Example: get("detection.zscore_threshold") → 3.0
    """
    cfg = get_config()
    keys = key_path.split(".")
    val = cfg

    for key in keys:
        if isinstance(val, dict) and key in val:
            val = val[key]
        else:
            return default

    return val
