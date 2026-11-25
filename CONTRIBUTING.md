# Contributing guidelines

## Pull Request Checklist

Before sending your pull requests, make sure you followed this list.

- Read [contributing guidelines](CONTRIBUTING.md).
- Read [Code of Conduct](CODE_OF_CONDUCT.md).


### How to contribute

If you'd like to contribute, start by searching through the issues and pull requests to see whether someone else has raised a similar idea or question.

If you don't see your idea listed, and you think it fits into the goals of this guide, do one of the following:

- If your contribution is minor, such as a typo fix, open a pull request.
- If your contribution is major, such as a new guide, start by opening an issue first. That way, other people can weigh in on the discussion before you do any work.

#### Community
Discussions about the Open Source Guides take place on this repository's [Issues](https://github.com/LDO-CERT/orochi/issues) and [Pull Requests](https://github.com/LDO-CERT/orochi/pulls) sections.
We have also available a public [gitter](https://gitter.im/ldo-cert-orochi/community) room and anybody is welcome to join these conversations.
Wherever possible, do not take these conversations to private channels, including contacting the maintainers directly.

#### Overview
Being an Open Source project, everyone can contribute, provided that it respect the following points:

- Before contributing any code, the author must make sure all tests work:
  ```bash
  # Locally with uv (only the Postgres container is needed, on localhost:5432):
  uv sync
  uv run pytest
  # Or inside the containers, built with --build-arg INSTALL_DEV=true:
  docker compose exec django_wsgi pytest
  ```
- If you add or update vendored frontend libraries (DataTables, Marked, SweetAlert2, TomSelect, etc.):
  1. Record the library and pinned version in `orochi/static/vendor_manifest.json`.
     If you have to patch a vendored file by hand, describe the change in the package `local_patch` field: `update_vendor_js` then warns that the patch must be re-applied after an update.
  2. Test updating and integrity signatures:
     ```bash
     docker compose exec django_wsgi python manage.py update_vendor_js --check
     docker compose exec django_wsgi python manage.py update_vendor_js --package <name> --update
     ```
  3. Ensure vendor asset tests pass without regressions:
     ```bash
     docker compose exec django_wsgi pytest orochi/website/tests/test_vendor_assets.py
     ```
- Developed code must adhere to syntax and linting standards enforced by Ruff (`uv run ruff check .` and `uv run ruff format --check .`).
- Code must be developed following the branching model.
- For any new feature added, automated tests should be provided, following the example of the ones already created.

#### Updating volatility3
The images patch volatility3 for Linux AArch64 (`compose/local/vol_fix/`). After changing the `volatility3` revision in `pyproject.toml`, the image build stops in `vol_fix/apply.sh` until `vol_fix/linux.py` is merged again with the new upstream `automagic/linux.py` and the checksum in `apply.sh` is updated. `orochi/website/tests/test_vol_fix.py` covers the merged stacker.
