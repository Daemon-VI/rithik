# Releasing to PyPI

Releases are published by `.github/workflows/publish.yml` through PyPI's trusted publishing.
PyPI trusts this one workflow in this one repository, so no API token exists anywhere, not in
repository secrets and not on anyone's machine.

## One-time setup

1. **On pypi.org**, open *Account settings -> Publishing* and add a **pending publisher**
   (a pending publisher is for a project that does not exist on PyPI yet):

   | Field | Value |
   |---|---|
   | PyPI project name | `rithik` |
   | Owner | `Daemon-VI` |
   | Repository name | `rithik` |
   | Workflow name | `publish.yml` |
   | Environment name | `pypi` |

   A pending publisher does not reserve the name. The first successful upload creates the
   project, and the publisher then becomes an ordinary trusted publisher for it.

2. **In the GitHub repository**, open *Settings -> Environments* and create an environment
   named `pypi`. The name must match exactly, because PyPI checks it. Adding yourself as a
   required reviewer is optional: it makes every upload wait for a click.

## Each release

1. Bump the version in **both** places, and keep them identical:
   - `version` in `pyproject.toml`
   - `__version__` in `src/rithik/__init__.py`

   `tests/test_cli.py` fails if the two differ.

2. Check that everything passes and that the package builds:

   ```sh
   uv run pytest -q
   uv run ruff check
   uv run ruff format --check
   uv build
   ```

3. Commit and push the change, then wait for CI to pass on `main`.

4. On GitHub, create a release (*Releases -> Draft a new release*) with a **new tag named
   `vX.Y.Z`** that matches the version, for example `v0.1.0`. Publish the release.

5. The `publish` workflow runs on the published release:
   - `build` checks that the tag matches both version strings, runs `uv build`, and uploads
     `dist/` as an artifact.
   - `publish` runs in the `pypi` environment with `id-token: write`, downloads the artifact,
     and uploads it with `pypa/gh-action-pypi-publish`, which exchanges the workflow's OIDC
     token with PyPI. No password or token is involved.

   A tag that does not match the version fails the `build` job before anything is uploaded.
   PyPI never accepts the same version twice, so a mistake means bumping to a new version.

## Verify

After the workflow finishes, check the release from a clean environment:

```sh
pipx install rithik          # or: pipx upgrade rithik
rithik --version             # should print the new version
uvx rithik@X.Y.Z --version   # runs the exact release without installing it
```

The project page is <https://pypi.org/project/rithik/>.
