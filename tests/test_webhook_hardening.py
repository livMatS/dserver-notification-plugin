"""Audit hardening tests: restrictive default IP filter and graceful
handling of malformed notification payloads."""

import os
import subprocess
import sys

SNIPPET = ("import dserver_notification_plugin.config as c; "
           "print(c.Config.ALLOW_ACCESS_FROM)")


def _config_default_in_subprocess(env_value=None):
    """Import the config in a clean interpreter and report the IP network.

    A subprocess is used because the value is computed at import time and
    reloading the module in-process would detach the Config class other
    modules already hold a reference to.
    """
    env = dict(os.environ)
    env.pop("DSERVER_NOTIFY_ALLOW_ACCESS_FROM", None)
    if env_value is not None:
        env["DSERVER_NOTIFY_ALLOW_ACCESS_FROM"] = env_value
    output = subprocess.run(
        [sys.executable, "-c", SNIPPET],
        env=env, capture_output=True, text=True, check=True)
    return output.stdout.strip()


def test_default_allow_access_from_is_loopback():
    """Without explicit configuration the webhook must NOT accept
    notifications from any IP (0.0.0.0/0)."""
    assert _config_default_in_subprocess() == "127.0.0.1/32"


def test_explicit_allow_access_from_honored():
    assert _config_default_in_subprocess("10.0.0.0/8") == "10.0.0.0/8"


def test_notify_json_without_records_is_400(tmp_app_with_users):  # NOQA
    """A syntactically valid JSON body without 'Records' must yield a
    clean 400, not an unhandled KeyError (500)."""
    response = tmp_app_with_users.post(
        "/webhook/notify",
        json={"Action": "Publish", "Message": "not an S3 event"},
    )
    assert response.status_code == 400


def test_notify_records_without_event_name_is_400(tmp_app_with_users):  # NOQA
    response = tmp_app_with_users.post(
        "/webhook/notify",
        json={"Records": [{"unexpected": "shape"}]},
    )
    assert response.status_code == 400


def test_notify_blocked_ip_rejected(tmp_app_with_users,
                                    access_restriction):  # NOQA
    response = tmp_app_with_users.post(
        "/webhook/notify",
        json={"Records": [{"eventName": "s3:ObjectCreated:Put", "s3": {}}]},
    )
    assert response.status_code == 403
