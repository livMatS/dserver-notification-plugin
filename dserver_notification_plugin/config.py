import ipaddress
import json
import logging
import os


logger = logging.getLogger(__name__)


CONFIG_SECRETS_TO_OBFUSCATE = []


class Config(object):
    # Dictionary for conversion of bucket names to base URIs
    BUCKET_TO_BASE_URI = json.loads(
        os.environ.get('DSERVER_NOTIFY_BUCKET_TO_BASE_URI',
                       '{"bucket": "s3://bucket"}'))

    # Limit notification access to this IP network. The webhook performs no
    # signature validation, so anyone in this network can trigger dataset
    # registration/deletion. Defaults to loopback only; deployments must
    # explicitly configure the network their storage backend notifies from.
    ALLOW_ACCESS_FROM = ipaddress.ip_network(
        os.environ.get('DSERVER_NOTIFY_ALLOW_ACCESS_FROM',
                       '127.0.0.1/32'))


if Config.ALLOW_ACCESS_FROM == ipaddress.ip_network('0.0.0.0/0'):
    logger.warning(
        "DSERVER_NOTIFY_ALLOW_ACCESS_FROM is set to 0.0.0.0/0: the "
        "unauthenticated notification webhook accepts S3 events from ANY "
        "IP address. Restrict this to your storage backend's network."
    )
