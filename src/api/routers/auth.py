from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.api.core.constants import VALID_ROLES
from src.api.core.rate_limit import limiter
from src.api.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    require_roles,
    verify_password,
)
from src.api.database import get_db
from src.api.models.user import UserDB
from src.api.schemas import LoginRequest, RefreshRequest, TokenResponse, UserResponse


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return TokenResponse(
        access_token=create_access_token(user.username, user.role),
        refresh_token=create_refresh_token(user.username, user.role),
    )


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
def refresh_token(request: Request, payload: RefreshRequest, db: Session = Depends(get_db)):
    token_payload = decode_token(payload.refresh_token)
    if token_payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    username = token_payload.get("sub")
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return TokenResponse(
        access_token=create_access_token(username, user.role),
        refresh_token=create_refresh_token(username, user.role),
    )


@router.get("/me", response_model=UserResponse)
def me(current_user: UserDB = Depends(require_roles(list(VALID_ROLES)))):
    return current_user
