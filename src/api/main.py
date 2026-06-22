from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.api.core.rate_limit import limiter
from src.api.core.config import settings
from src.api.core.security import get_password_hash
from src.api.database_compat import ensure_soc_lite_schema_compatibility
from src.api.database import engine
from src.api.models import UserDB
from src.api.routers import admin, alerts, auth, settings as settings_router, stats
from src.normalizer.db import Base


BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "static" / "dashboard"

app = FastAPI(title="University Threat Detection API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(admin.router)
app.include_router(settings_router.router)


@app.get("/dashboard", include_in_schema=False)
def dashboard_root():
    return RedirectResponse(url="/dashboard/login.html")


@app.get("/dashboard/", include_in_schema=False)
def dashboard_root_slash():
    return RedirectResponse(url="/dashboard/login.html")


app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


@app.get("/")
def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.on_event("startup")
def startup_provisioning() -> None:
    Base.metadata.create_all(engine)
    ensure_soc_lite_schema_compatibility(engine)

    with Session(engine) as session:
        try:
            users_count = session.query(UserDB).count()
            if users_count == 0:
                admin_username, admin_password = settings.require_default_admin_credentials()
                admin_user = UserDB(
                    username=admin_username,
                    hashed_password=get_password_hash(admin_password),
                    role="admin",
                )
                session.add(admin_user)
                session.commit()
        except IntegrityError:
            session.rollback()
