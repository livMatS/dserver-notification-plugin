# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A plugin for [dservercore](https://github.com/livMatS/dservercore) (the dtool lookup server). It exposes a single unauthenticated webhook, `POST /webhook/notify`, that receives **S3 event notifications** from an S3-compatible storage backend (minio, NetApp StorageGRID, AWS S3) and keeps the lookup server's dataset index in sync: registering/updating datasets on object-created events and deregistering them on object-removed events.

The plugin is discovered by dservercore via the `dservercore.extension` entry point (see `pyproject.toml`), which points at `NotificationExtension`. Everything lives in a single module, `dserver_notification_plugin/__init__.py`, plus `config.py`.

## Commands

```bash
# Tests require a running MongoDB (used by the mongo retrieve/search plugins pulled in for tests)
cd tests/container && docker-compose up -d   # starts mongodb on localhost:27017
cd ../..

pip install -e .[test]                        # install with test extras

pytest                                        # full suite (pyproject enables --cov)
pytest -sv                                    # verbose, as CI runs it
pytest --log-cli-level=DEBUG                  # stream debug logs (useful for the webhook flow)
pytest tests/test_webhook_routes.py::test_webhook_notify_route   # single test

# Override mongo location if not on localhost
TEST_MONGO_URI=mongodb://host:27017/ pytest

# Lint (CI uses flake8; syntax/undefined-name errors fail the build)
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```

CI (`.github/workflows/test.yml`) installs `dservercore`, `dserver-search-plugin-mongo`, and `dserver-retrieve-plugin-mongo` from their git `main` branches — these are not pinned, so test breakage can originate upstream.

## Configuration (environment variables)

Both are read once at import time in `config.py` into the `Config` class:

- `DSERVER_NOTIFY_BUCKET_TO_BASE_URI` — JSON map of S3 bucket name → dtool base URI, e.g. `{"bucket": "ecs://bucket"}`. A notification for a bucket not in this map is rejected with HTTP 400.
- `DSERVER_NOTIFY_ALLOW_ACCESS_FROM` — CIDR network allowed to reach the webhook. **Defaults to `127.0.0.1/32` (loopback only).** The webhook does no signature validation, so anyone in this range can trigger registration/deletion. Setting `0.0.0.0/0` logs a warning at import.

## Architecture / control flow

The request lifecycle in `__init__.py` is the thing to understand before editing:

1. **`@filter_ips` decorator** — wraps `notify()`. Resolves the client IP by checking, in order, headers `HTTP_X_REAL_IP`, `X-Forwarded-For`, `X-Real-IP`, then `request.remote_addr`. This ordering matters for deployments behind a reverse proxy. Rejects with 403 if the IP is not in `Config.ALLOW_ACCESS_FROM`.

2. **`notify()`** — content-type dispatch. `application/json` is read directly; `application/x-www-form-urlencoded` is the **NetApp StorageGRID SNS** shape, where the real S3 event is a JSON string inside the form's `Message` field. A form post with no parseable `Message` (StorageGRID health check) returns 200 with no body. Malformed payloads (missing `Records`/`eventName`/`s3`) return 400 via `abort(400, description=...)` — note `abort` takes `description=`, not `message=`.

3. **`_process_event()`** — matches `eventName` against `OBJECT_CREATED_EVENT_NAMES` / `OBJECT_REMOVED_EVENT_NAMES`. These lists contain both the `s3:`-prefixed AWS/minio names **and** the unprefixed names StorageGRID emits — when adding event handling, add both variants. Bucket name and object key are URL-unquoted here.

4. **`_reconstruct_uri()` + `_parse_obj_key()` + `_retrieve_uri()`** — the core dtool-specific logic. An S3 object key does not directly give a dataset URI. The strategy: extract the **first v4 UUID** from the object key (`UUID_REGEX`), then look up an existing `(base_uri, uuid)` dataset row in the SQL DB to get its real URI; if none exists, synthesize one with `dtoolcore._generate_uri`. The long comment block in `_reconstruct_uri` explains why naive top-level-`dtool-{UUID}` handling is insufficient (object creation order is not guaranteed, metadata updates may not touch the link object). The `(base_uri, uuid) <-> uri` mapping is only bijective for the S3 broker.

5. **Created** (`_process_object_created`) — brute-force re-registers on *every* object write (notifications can arrive out of order), loading the dataset via `dtoolcore.DataSet.from_uri` and calling dservercore's `register_dataset`. A `DtoolCoreTypeError` means the dataset is only partially copied — swallowed silently, expecting a later finalizing notification.

6. **Removed** (`_process_object_removed`) — only deletes the index entry when the object key ends in `/dtool` (the dataset's marker object), then deletes matching `Dataset` rows directly via SQLAlchemy.

`NotificationExtension` (subclass of `dservercore.ExtensionABC`) is the glue: `get_blueprint()` returns `webhook_bp`, `get_config()` returns the `Config` class. `init_app` and `register_dataset` are intentional no-ops.

## Conventions specific to this repo

- **Versioning** is via `setuptools_scm` / `flit_scm` from git tags — there is no hardcoded version; `dserver_notification_plugin/version.py` is generated (write_to) and gitignored. Don't edit it.
- **Build backend is flit** (`flit_scm:buildapi`), recently migrated from setuptools.
- The README documents end-to-end webhook setup for **minio** (`mc admin config set ... notify_webhook`) and **NetApp StorageGRID** (SNS endpoint + `NotificationConfiguration` XML). Keep it in sync when changing event handling or the route.
- `doc/sample_requests/` contains real captured request logs (webhook + elasticsearch variants) — useful reference payloads when reasoning about event shapes.
- `tests/data/1a1f9fad-...` is a real on-disk dtool dataset fixture; `tests/data/mock_event.json` is the sample S3 event used by `request_json`.
