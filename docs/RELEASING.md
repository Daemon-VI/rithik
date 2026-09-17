# Releasing to PyPI and npm

Releases are published by `.github/workflows/publish.yml` through trusted publishing on both
PyPI and npm. Each registry trusts this one workflow in this one repository, so no API token
exists anywhere, not in repository secrets and not on anyone's machine.

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

3. **npm, first publish only.** npm configures a trusted publisher on an existing package, so
   the very first version is published by hand from a signed-in machine:

   ```sh
   npm login                 # opens the browser; use your own npm account
   npm test
   npm publish               # asks for a one-time password if 2FA is on
   ```

   Then, on npmjs.com, open the package's *Settings -> Trusted publishing*, choose GitHub
   Actions, and enter owner `Daemon-VI`, repository `rithik` and workflow `publish.yml`, with
   the environment left blank. After that, set *Publishing access* to require 2FA and
   disallow tokens, so the workflow is the only way to publish.

   Trusted publishing needs `repository.url` in `package.json` to match the GitHub repository
   exactly (`git+https://github.com/Daemon-VI/rithik.git`), and npm CLI 11.5.1 or later, which
   the workflow installs.

## Each release

1. Bump the version in **all three** places, and keep them identical:
   - `version` in `pyproject.toml`
   - `__version__` in `src/rithik/__init__.py`
   - `version` in `package.json`

   `tests/test_cli.py` fails if the first two differ. `npm test` fails if `package.json`
   differs, because the golden `--version` output comes from the Python side. The publish
   workflow checks all three against the tag.

2. Check that everything passes and that the package builds:

   ```sh
   uv run pytest -q
   uv run ruff check
   uv run ruff format --check
   uv build
   uv run python scripts/export_golden.py --check
   npm test
   ```

3. Commit and push the change, then wait for CI to pass on `main`.

4. On GitHub, create a release (*Releases -> Draft a new release*) with a **new tag named
   `vX.Y.Z`** that matches the version, for example `v0.1.0`. Publish the release.

5. The `publish` workflow runs on the published release:
   - `build` checks that the tag matches all three version strings, runs `uv build`, and uploads
     `dist/` as an artifact.
   - `pypi` runs in the `pypi` environment with `id-token: write`, downloads the artifact,
     and uploads it with `pypa/gh-action-pypi-publish`, which exchanges the workflow's OIDC
     token with PyPI. No password or token is involved.
   - `npm` runs `npm test` and then `npm publish`. npm exchanges the OIDC token itself and
     attaches a provenance attestation.

   A tag that does not match the version fails the `build` job before anything is uploaded.
   PyPI never accepts the same version twice, so a mistake means bumping to a new version.

## Verify

After the workflow finishes, check the release from a clean environment:

```sh
pipx install rithik          # or: pipx upgrade rithik
rithik --version             # should print the new version
uvx rithik@X.Y.Z --version   # runs the exact release without installing it
npx rithik@X.Y.Z --version   # the npm release
```

The project pages are <https://pypi.org/project/rithik/> and
<https://www.npmjs.com/package/rithik>.
