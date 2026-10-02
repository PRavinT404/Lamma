import os
import shutil

def clear_cache():
    """Clear the application's cache."""
    cache_dirs = [".cache_ai", "llm_cache"]
    for cache_dir in cache_dirs:
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
            print(f"Cache directory '{cache_dir}' cleared.")

def get_config():
    # This is a placeholder for a more robust config management system
    return None

def set_config(config):
    # This is a placeholder for a more robust config management system
    pass