# Quick Start: Publishing to PyPI

This is a condensed guide to get your package published to PyPI quickly. For detailed instructions, see [PUBLISHING.md](PUBLISHING.md).

## Prerequisites Setup (One-Time)

1. **Create PyPI accounts**:
   - [TestPyPI](https://test.pypi.org/account/register/) (for testing)
   - [PyPI](https://pypi.org/account/register/) (production)

2. **Generate API tokens**:
   - TestPyPI: https://test.pypi.org/manage/account/#api-tokens
   - PyPI: https://pypi.org/manage/account/#api-tokens

3. **Install tools**:
   ```bash
   pip install build twine
   ```

4. **Configure authentication** (`~/.pypirc`):
   ```ini
   [distutils]
   index-servers =
       pypi
       testpypi

   [pypi]
   username = __token__
   password = pypi-YOUR_PRODUCTION_TOKEN_HERE

   [testpypi]
   repository = https://test.pypi.org/legacy/
   username = __token__
   password = pypi-YOUR_TEST_TOKEN_HERE
   ```

## Publishing Steps

### 1. Update Version
Edit these files with new version (e.g., `0.1.0`):
- `pyproject.toml` → `version = "0.1.0"`
- `src/vortex_sdk/__init__.py` → `__version__ = "0.1.0"`
- `CHANGELOG.md` → Add new version entry

### 2. Test First (TestPyPI)
```bash
# From packages/vortex-python-sdk directory
rm -rf dist/ build/ *.egg-info/
python -m build
python -m twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ vortex-python-sdk
```

### 3. Publish to Production (PyPI)
```bash
python -m twine upload dist/*
```

### 4. Verify
```bash
pip install vortex-python-sdk
python -c "from vortex_sdk import Vortex; print('Success!')"
```

## Done! 🎉

Your package is now available for anyone to install with:
```bash
pip install vortex-python-sdk
```

## Automated Publishing (Optional)

For GitHub-based automatic publishing:

1. **Add GitHub Secrets**:
   - `PYPI_API_TOKEN` - Your PyPI token
   - `TEST_PYPI_API_TOKEN` - Your TestPyPI token

2. **Create Release**:
   - GitHub → Releases → "Create a new release"
   - Tag: `v0.1.0`
   - GitHub Actions will automatically publish

See [PUBLISHING.md](PUBLISHING.md) for detailed automated setup instructions.