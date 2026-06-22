import os

from dotenv import load_dotenv


load_dotenv()


class Settings:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL")
        self.jwt_secret_key = os.getenv("JWT_SECRET_KEY")
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
        self.refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        self.default_admin_username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
        self.default_admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD")

        if not self.database_url:
            raise ValueError(
                "DATABASE_URL is missing. Define it in .env (example: "
                "postgresql+psycopg2://analyst:CHANGE_ME_STRONG_POSTGRES_PASSWORD@localhost:5432/threat_detection)."
            )
        if not self.jwt_secret_key:
            raise ValueError(
                "JWT_SECRET_KEY is missing. Generate a secure key and set it in .env."
            )

    def require_default_admin_credentials(self) -> tuple[str, str]:
        if not self.default_admin_password:
            raise ValueError(
                "DEFAULT_ADMIN_PASSWORD is missing. Define DEFAULT_ADMIN_USERNAME and "
                "DEFAULT_ADMIN_PASSWORD in .env before first startup."
            )
        return self.default_admin_username, self.default_admin_password


settings = Settings()
