# Publishing to TestPyPI and PyPI

This guide documents how to publish **promql-analyzer** to TestPyPI and then to real PyPI.

Do **not** publish automatically without reviewing the built artifacts.

---

## What you already have

- `pyproject.toml` with package name, version, dependencies, and CLI entry point
- `src/promql_analyzer/` package layout
- `README.md` and `LICENSE` (MIT)
- Local install works with `pip install -e .`

---

## Step 0 — Check the package name is free

```bash
pip index versions promql-analyzer
```

Or open: https://pypi.org/project/promql-analyzer/

If the name is taken, change `name` in `pyproject.toml` before the first upload.

---

## Step 1 — Confirm metadata

In `pyproject.toml`, confirm:

- `name = "promql-analyzer"`
- `version = "0.1.0"`
- `authors` (update email if still a placeholder)
- `[project.urls]` pointing at the GitHub repo

Also keep versions in sync:

- `pyproject.toml` → `version = "0.1.0"`
- `src/promql_analyzer/__init__.py` → `__version__ = "0.1.0"`

---

## Step 2 — Create accounts and API tokens

1. Create an account on https://pypi.org and enable **2FA**
2. Create an account on https://test.pypi.org and enable **2FA**
3. Create an **API token** on each site:
   - Account settings → API tokens
   - Scope: **Entire account** for the first upload
   - Copy the token (`pypi-...`) — it is shown only once

When uploading:

- Username: `__token__`
- Password: the API token value (`pypi-...`)

Never commit tokens to git.

---

## Step 3 — Use the project virtualenv for building

Build from the **project** `.venv`, not from a TestPyPI install/test venv.

```bash
cd /Users/ranga/Documents/projects/promql-analyzer
source .venv/bin/activate
pip install -e ".[dev]"
```

The `dev` extras include `build` and `twine`.

If you see:

```text
No module named build
```

you are probably in the wrong venv. Switch back to `.venv` and install `[dev]`.

---

## Step 4 — Quality checks before release

```bash
pytest
ruff check src tests
```

Both should pass.

---

## Step 5 — Build the package

```bash
rm -rf dist build *.egg-info src/*.egg-info
python -m build
python -m twine check dist/*
```

Expected output files:

```text
dist/promql_analyzer-0.1.0-py3-none-any.whl
dist/promql_analyzer-0.1.0.tar.gz
```

`twine check` should report **PASSED**.

---

## Step 6 — Test the built wheel in a clean venv

```bash
python -m venv /tmp/pqa-dist-test
/tmp/pqa-dist-test/bin/pip install dist/*.whl
/tmp/pqa-dist-test/bin/promql-analyze --version
/tmp/pqa-dist-test/bin/promql-analyze dude-look 'up'
/tmp/pqa-dist-test/bin/python -c "from promql_analyzer import dude_look; print(dude_look('up').complexity.score)"
```

If this works, packaging is correct.

---

## Step 7 — Upload to TestPyPI

```bash
python -m twine upload --repository testpypi dist/*
```

Prompts:

- Username: `__token__`
- Password: your **TestPyPI** API token

### Install from TestPyPI

Use a separate temporary venv for this:

```bash
python -m venv /tmp/pqa-testpypi
source /tmp/pqa-testpypi/bin/activate
pip install -i https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple \
  promql-analyzer
promql-analyze dude-look 'up'
```

`--extra-index-url https://pypi.org/simple` is required so dependencies such as `promql-parser` and `PyYAML` can still be installed from real PyPI.

This TestPyPI venv is for **install/test only**. Do not run `python -m build` from it unless you also install `build` there.

---

## Step 8 — Upload to real PyPI

Rebuild clean first (recommended):

```bash
cd /Users/ranga/Documents/projects/promql-analyzer
source .venv/bin/activate
rm -rf dist build
python -m build
python -m twine upload dist/*
```

Prompts:

- Username: `__token__`
- Password: your **real PyPI** API token

### Verify

```bash
pip install promql-analyzer
promql-analyze --version
```

Package page:

https://pypi.org/project/promql-analyzer/

---

## Step 9 — Tag the GitHub release

```bash
git tag v0.1.0
git push origin v0.1.0
```

Optional: create a GitHub Release from that tag.

---

## Later releases (0.1.1, 0.2.0, ...)

1. Bump version in `pyproject.toml` and `__init__.py`
2. Update docs/changelog if needed
3. Run `pytest` and `ruff check src tests`
4. Rebuild:

   ```bash
   rm -rf dist build
   python -m build
   ```

5. Upload:

   ```bash
   python -m twine upload dist/*
   ```

6. Tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

**Important:** PyPI versions are immutable. You cannot overwrite an already published version such as `0.1.0`.

---

## Common mistakes

| Mistake | Fix |
|--------|-----|
| Using GitHub password instead of token | Use username `__token__` and a PyPI API token |
| Building inside `/tmp/pqa-testpypi` | Build from project `.venv` with `.[dev]` installed |
| Forgetting to bump version | Always bump before re-upload |
| Skipping clean-wheel smoke test | Always test `dist/*.whl` in a fresh venv |
| Skipping TestPyPI | Use TestPyPI first to catch metadata/name issues |
| Committing secrets | Never commit API tokens |

---

## Minimal command path

```bash
cd /Users/ranga/Documents/projects/promql-analyzer
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests
rm -rf dist build
python -m build
python -m twine check dist/*
python -m twine upload --repository testpypi dist/*
# verify install from TestPyPI in a separate venv
python -m twine upload dist/*
```
