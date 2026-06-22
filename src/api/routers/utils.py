from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status


def parse_hours_param(hours: str | None) -> int | None:
    if hours is None or hours == "" or hours == "all":
        return None

    try:
        parsed = int(hours)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="hours must be an integer between 1 and 168 or 'all'",
        ) from exc

    if parsed < 1 or parsed > 168:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="hours must be between 1 and 168 or 'all'",
        )

    return parsed


def hours_cutoff(hours: str | None) -> datetime | None:
    parsed_hours = parse_hours_param(hours)
    if parsed_hours is None:
        return None
    return datetime.now(timezone.utc) - timedelta(hours=parsed_hours)
