"""Entry point for `python -m secscan …` — thin wrapper around the Typer CLI."""
from .cli import app

if __name__ == "__main__":
    app()
