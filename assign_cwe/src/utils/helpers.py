# Add to utils/helpers.py or similar
def safe_access(obj, key, default=None):
    """Safely access attribute or key from an object or dictionary."""
    if obj is None:
        return default
    
    if isinstance(obj, dict):
        return obj.get(key, default)
    else:
        try:
            return getattr(obj, key, default)
        except (AttributeError, TypeError):
            return default