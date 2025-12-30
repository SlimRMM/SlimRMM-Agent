"""
SlimRMM Agent - Configuration Module
Copyright (c) 2025 Kiefer Networks

Provides configuration loading and management for the agent.
"""

import os
import json
import logging
from service_utils import get_install_dir, CONFIG_FILENAME


def save_config(config_data):
    """
    Save configuration to the config file.

    Args:
        config_data: Configuration dictionary to save.
    """
    config_path = os.path.join(get_install_dir(), CONFIG_FILENAME)
    try:
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=4)
        # Set restrictive permissions
        os.chmod(config_path, 0o600)
        logging.info(f"Saved config to {config_path}")
    except Exception as e:
        logging.error(f"Error saving config: {e}")
        raise


def load_config():
    """
    Load the agent configuration from the config file.

    Returns:
        dict: Configuration dictionary with server, uuid, and api_key.
    """
    target_dir = get_install_dir()
    config_path = os.path.join(target_dir, CONFIG_FILENAME)

    # Also check for legacy config file
    legacy_config_path = os.path.join(target_dir, '.rmm_config.json')
    old_legacy_path = os.path.join('/var/lib/rmm', '.rmm_config.json')

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    elif os.path.exists(legacy_config_path):
        # Migrate legacy config
        logging.info(f"Migrating legacy config from {legacy_config_path}")
        with open(legacy_config_path, 'r') as f:
            config = json.load(f)
        save_config(config)
        os.remove(legacy_config_path)
        return config
    elif os.path.exists(old_legacy_path):
        # Migrate from old installation directory
        logging.info(f"Migrating config from old installation: {old_legacy_path}")
        with open(old_legacy_path, 'r') as f:
            config = json.load(f)
        save_config(config)
        return config
    else:
        logging.error(f"No config file found at {config_path}. Please install first.")
        raise FileNotFoundError(f"Configuration file not found at {config_path}")


def get_config_value(key, default=None):
    """
    Get a specific configuration value.

    Args:
        key: Configuration key to retrieve.
        default: Default value if key not found.

    Returns:
        The configuration value or default.
    """
    try:
        config = load_config()
        return config.get(key, default)
    except FileNotFoundError:
        return default
