# Publishing the Vortex Python SDK to PyPI

This guide walks you through publishing the Vortex Python SDK to PyPI so users can install it with `pip install vortex-python-sdk`.

## Prerequisites

1. **PyPI Account**: Create accounts on both:
   - [TestPyPI](https://test.pypi.org/account/register/) (for testing)
   - [PyPI](https://pypi.org/account/register/) (for production)

2. **API Tokens**: Generate API tokens (recommended over username/password):
   - TestPyPI: https://test.pypi.org/manage/account/#api-tokens
   - PyPI: https://pypi.org/manage/account/#api-tokens

3. **Required Tools**:
   ```bash
   pip install build twine
   ```

## Manual Publishing Process

### Step 1: Prepare the Package

```bash
# Navigate to the package directory
cd packages/vortex-python-sdk

# Clean any previous builds
rm -rf dist/ build/ *.egg-info/

# Install development dependencies
pip install -e ".[dev]"

# Run tests (create tests first)
pytest

# Format and lint code
black src/
isort src/
ruff check src/
mypy src/
```

### Step 2: Update Version

Edit [`pyproject.toml`](pyproject.toml):
```toml
[project]
version = "0.1.0"  # Update version number
```

Update [`CHANGELOG.md`](CHANGELOG.md) with new version details.

Update [`src/vortex_sdk/__init__.py`](src/vortex_sdk/__init__.py):
```python
__version__ = "0.1.0"
```

### Step 3: Build the Package

```bash
# Build source distribution and wheel
python -m build
```

This creates:
- `dist/vortex_python_sdk-0.1.0.tar.gz` (source distribution)
- `dist/vortex_python_sdk-0.1.0-py3-none-any.whl` (wheel)

### Step 4: Test on TestPyPI First

```bash
# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ vortex-python-sdk
```

### Step 5: Publish to PyPI

```bash
# Upload to production PyPI
python -m twine upload dist/*
```

### Step 6: Verify Installation

```bash
# Install from PyPI
pip install vortex-python-sdk

# Test import
python -c "from vortex_sdk import Vortex; print('Success!')"
```

## Authentication Methods

### Method 1: API Token (Recommended)

Create `~/.pypirc`:
```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR_API_TOKEN_HERE

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TEST_API_TOKEN_HERE
```

### Method 2: Environment Variables

```bash
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-YOUR_API_TOKEN_HERE

# For TestPyPI
export TWINE_REPOSITORY=testpypi
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-YOUR_TEST_API_TOKEN_HERE
```

### Method 3: Interactive (Less Secure)

Twine will prompt for username/password if no config is found.

## Automated Publishing with GitHub Actions

### Step 1: Add Secrets to GitHub

In your GitHub repository settings, add these secrets:
- `PYPI_API_TOKEN` - Your PyPI API token
- `TEST_PYPI_API_TOKEN` - Your TestPyPI API token

### Step 2: Create Workflow File

Create [`.github/workflows/publish.yml`](.github/workflows/publish.yml):

```yaml
name: Publish Python Package

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      publish_to_testpypi:
        description: 'Publish to TestPyPI instead of PyPI'
        required: false
        default: false
        type: boolean

jobs:
  publish:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.8'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install build twine

    - name: Build package
      run: python -m build
      working-directory: packages/vortex-python-sdk

    - name: Publish to TestPyPI
      if: \${{ github.event.inputs.publish_to_testpypi == 'true' }}
      uses: pypa/gh-action-pypi-publish@release/v1
      with:
        user: __token__
        password: \${{ secrets.TEST_PYPI_API_TOKEN }}
        repository_url: https://test.pypi.org/legacy/
        packages_dir: packages/vortex-python-sdk/dist/

    - name: Publish to PyPI
      if: \${{ github.event.inputs.publish_to_testpypi != 'true' }}
      uses: pypa/gh-action-pypi-publish@release/v1
      with:
        user: __token__
        password: \${{ secrets.PYPI_API_TOKEN }}
        packages_dir: packages/vortex-python-sdk/dist/
```

## Release Process

### For Manual Releases

1. **Update version** in `pyproject.toml`, `__init__.py`, and `CHANGELOG.md`
2. **Commit changes**: `git commit -am "Release v0.1.0"`
3. **Create tag**: `git tag v0.1.0`
4. **Push**: `git push && git push --tags`
5. **Build and publish** following steps above

### For Automated Releases

1. **Update version** and commit changes
2. **Create GitHub Release**:
   - Go to your GitHub repository
   - Click "Releases" → "Create a new release"
   - Tag version: `v0.1.0`
   - Release title: `v0.1.0`
   - Describe changes
   - Click "Publish release"
3. **GitHub Actions will automatically publish to PyPI**

## Version Management

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Incompatible API changes
- **MINOR** version: New functionality (backward compatible)
- **PATCH** version: Bug fixes (backward compatible)

Examples:
- `0.1.0` - Initial stable release
- `0.1.1` - Bug fix
- `0.2.0` - New features
- `1.0.0` - First major release

## Troubleshooting

### Common Issues

1. **Package name already exists**: Choose a different name in `pyproject.toml`
2. **Upload failed**: Check your API token and network connection
3. **Version conflicts**: Ensure version number is higher than existing versions
4. **Missing files**: Check `MANIFEST.in` includes all necessary files

### Verification Commands

```bash
# Check package contents
python -m tarfile -l dist/vortex-python-sdk-0.1.0.tar.gz

# Validate package
python -m twine check dist/*

# Test local installation
pip install dist/vortex-python-sdk-0.1.0.tar.gz
```

## Post-Publication

After successful publication:

1. **Update demo apps** to use published package:
   ```bash
   # In demo apps, replace local installation with:
   pip install vortex-python-sdk
   ```

2. **Update documentation** with installation instructions

3. **Announce the release** on relevant channels

4. **Monitor for issues** and user feedback

## Security Best Practices

1. **Use API tokens** instead of username/password
2. **Limit token scope** to specific packages if possible
3. **Rotate tokens** regularly
4. **Never commit tokens** to version control
5. **Use repository secrets** in GitHub Actions
6. **Enable 2FA** on PyPI accounts

## Resources

- [Python Packaging User Guide](https://packaging.python.org/)
- [PyPI Help](https://pypi.org/help/)
- [TestPyPI](https://test.pypi.org/)
- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)