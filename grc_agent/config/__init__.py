"""Application configuration loaded from environment variables / .env via
pydantic-settings.

Deliberately does not re-export from `settings` here: eagerly importing a
submodule in a package's `__init__.py` breaks `python -m grc_agent.config.settings`
(the module ends up double-imported, once as itself and once as `__main__`).
Import directly: `from grc_agent.config.settings import Settings, get_settings`.
"""
