"""Pydantic schemas for the feature extraction layer."""

from typing import Optional

from pydantic import BaseModel


class FeatureWindow(BaseModel):
    """One feature record covering a fixed time window for a single source IP."""

    feature_id: str  # UUID4
    window_start: str  # ISO8601
    window_end: str  # ISO8601
    window_size_min: int  # 5 or 15

    ip: str  # Source IP

    # Core features
    request_rate: float  # Requests per minute within the window
    login_fail_count: int  # Failed login attempts
    ip_entropy: float  # Shannon entropy of IP distribution across the window
    endpoint_frequency: dict  # {"/path": count} — top-10 endpoints
    unique_users: int  # Distinct usernames observed

    # Extended features
    user_agent_entropy: float  # Shannon entropy of User-Agent strings
    bytes_per_request: float  # Average bytes sent per request
    port_entropy: float  # Shannon entropy of destination ports

    # Source of dominant log evidence in this window. Set by extract_from_X
    # (single source) or by merge_features (priority: firewall > auth > nginx).
    source: Optional[str] = None  # "nginx" | "auth" | "firewall" | None

    # Optional ground-truth label (for evaluation only)
    label: Optional[str] = None  # "normal" | "attack" | None
