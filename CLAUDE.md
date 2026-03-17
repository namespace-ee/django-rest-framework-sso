# CLAUDE.md

## Project

Single sign-on extension for Django REST Framework. Uses JWT tokens (PyJWT) with RSA key pairs for session and authorization tokens.

## Commands

```bash
uv run ruff check .           # Lint
uv run ruff format .          # Format (use --check to verify)
uv run pytest tests/ -v       # Run tests
uv build                      # Build package
```

## Code style

- Ruff with rules E, F, I (errors, pyflakes, isort)
- Line length: 120
- Target: Python 3.10

## Supported versions

- Python: 3.10, 3.11, 3.12, 3.13, 3.14
- Django: 4.2, 5.2, 6.0

## CI matrix

| Django | Python |
|--------|--------|
| 4.2 | 3.10, 3.12 |
| 5.2 | 3.10, 3.12, 3.13, 3.14 |
| 6.0 | 3.12, 3.13, 3.14 |

## CI pipeline

1. **Lint** - ruff check + ruff format --check
2. **Test** - pytest across the full Django/Python matrix
3. **Build** - `uv build` (on release or workflow_dispatch)
4. **Publish** - PyPI via OIDC trusted publishing (on GitHub release)

## Project structure

- `rest_framework_sso/` - main package
- `tests/` - pytest + pytest-django, settings in `tests/settings.py`
- `tests/keys/` - RSA test key files (.pem)

## Versioning

Uses `bump-my-version`. Updates version in both `pyproject.toml` and `rest_framework_sso/__init__.py`.
