# Packaging layout

This repository is a standalone Python distribution.

- Distribution name: `mt-media-sdk`
- Import package: `mt_media_sdk`
- Package source: `src/mt_media_sdk/`

Do not move `pyproject.toml` into the package directory and do not configure
setuptools to search `..`. The repository must remain independently buildable
when cloned by pip from Git.

Validate before pushing:

```bash
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
python -m zipfile -l dist/mt_media_sdk-*.whl
python -m pip install --force-reinstall --no-deps dist/mt_media_sdk-*.whl
python -c "import mt_media_sdk; print(mt_media_sdk.__file__)"
```
