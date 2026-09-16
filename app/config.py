"""Application config, loaded from env variables and .env

everything that might differ between your laptop, CI and a container lives here,
and NOTHING else does. if changing a value would require
rebuilding the docker image, it belongs in code; if it should be changeable at
deploy time, it belongs here."""

from __future__ import annotations

from functools import lru_cache

# lru_cache = "Least Recently Used Cache"
# the same argument return the same object without re-running the body
from pydantic import Field

# field attaches metadata and validation rules to a model attribute
from pydantic_settings import BaseSettings, SettingsConfigDict

# this is the separate package that reeds configs from the env.
# baseSettings looks up each field by name
# in os.environ and in the .env file, then VALIDATES AND CONVERTS it - so
# SCSRA_CVSS_THRESHOLD="7.5" arrives in Python as the float 7.5, and
# "banana" fails loudly at startup instead of silently at 3am.


class Settings(BaseSettings):
    """Runtime configuration. Field names map to SCSRA_<UPPERCASE> env vars."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SCSRA_",
        extra="ignore",
    )
    # env_prefix namespaces our variables so SCSRA_DEBUG can never collide with
    # some other tool's DEBUG.
    # extra="ignore" means unknown variables in .env are skipped rather than
    # raising - necessary because a real .env also holds variables for other
    # tools.

    # identity
    app_name: str = "Semantic Cyber-Security & Risk Analytics API"
    version: str = "0.1.0"
    api_prefix: str = "/api/v1"
    # Versioning the URL path from day one. Once someone depends on your API,
    # /api/v1 lets you ship a breaking /api/v2 without breaking them.

    debug: bool = False

    # analysis parameters
    cvss_threshold: float = Field(
        default=7.0,
        ge=0.0,
        le=10.0,
        description="Minimum CVSS v3.1 base score for a vulnerability to be "
        "treated as exploitable. 7.0 is the HIGH boundary.",
    )
    max_attack_depth: int = Field(
        default=6,
        ge=1,
        le=15,
        description="Maximum number of hops explored when enumerating attack paths.",
    )
    # ge/le are enforced at startup. A typo of 70.0 fails immediately with a
    # clear message, instead of producing an empty report nobody questions.

    # SPARQL endpoint
    enable_sparql_endpoint: bool = True
    sparql_max_rows: int = Field(default=1000, ge=1, le=100_000)

    # CORS
    cors_origins: list[str] = ["*"]
    # CORS = Cross-Origin Resource Sharing. A browser refuses to let JavaScript
    # from site A read a response from site B unless B says it is allowed.
    # "*" means "any site", which is fine for a public read-only demo and wrong
    # for anything with authentication. Flagged again in main.py.


@lru_cache
def get_settings() -> Settings:
    """Build once and return the settings object"""
    return Settings()


settings = get_settings()
