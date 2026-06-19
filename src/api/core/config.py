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

        if not self.database_url:
            raise ValueError(
                "DATABASE_URL is missing. Define it in .env (example: "
                "postgresql+psycopg2://analyst:changeme_dev@localhost:5432/threat_detection)."
            )
        if not self.jwt_secret_key:
            raise ValueError(
                "JWT_SECRET_KEY is missing. Generate a secure key and set it in .env."
            )


settings = Settings()
