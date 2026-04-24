"""Runtime settings — env + .env file, with Path-typed workdir helpers.

Settings fields map 1:1 to env vars (pydantic-settings does the binding).
`settings.ensure_dirs()` is called at the start of every scan command.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    github_token: str | None = None
    lmstudio_host: str = "localhost:1234"
    secscan_model: str | None = None
    secscan_workdir: Path = Path("./.secscan")
    secscan_exploit_confirm: bool = True

    @property
    def clones_dir(self) -> Path:
        return self.secscan_workdir / "clones"

    @property
    def reports_dir(self) -> Path:
        return self.secscan_workdir / "reports"

    @property
    def exploits_dir(self) -> Path:
        return self.secscan_workdir / "exploits"

    def ensure_dirs(self) -> None:
        for d in (self.clones_dir, self.reports_dir, self.exploits_dir):
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()
