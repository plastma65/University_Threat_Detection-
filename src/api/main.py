from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.api.core.rate_limit import limiter
from src.api.core.security import get_password_hash
from src.api.database import engine
from src.api.models import AlertDB, UserDB
from src.api.routers import alerts, auth, stats
from src.normalizer.db import Base


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


@app.get("/")
def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.on_event("startup")
def startup_provisioning() -> None:
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        try:
            users_count = session.query(UserDB).count()
            if users_count == 0:
                admin_user = UserDB(
                    username="admin",
                    hashed_password=get_password_hash("admin123"),
                    role="admin",
                )
                session.add(admin_user)
                session.commit()
        except IntegrityError:
            session.rollback()
