"""Receive and process Amazon S3 event notifications."""
try:
    from importlib.metadata import version, PackageNotFoundError
except ModuleNotFoundError:
    from importlib_metadata import version, PackageNotFoundError

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    # package is not installed
    __version__  = None

if __version__ is None:
    try:
        del __version__
        from .version import __version__
    except:
        __version__ = None


import ipaddress
import json
import logging
import re
import urllib

from functools import wraps

import dtoolcore, dtool_s3

from dservercore import (
    sql_db,
    ValidationError,
    ExtensionABC
)
from dservercore.sql_models import (
    BaseURI,
    Dataset,
)
from dservercore.utils import (
    base_uri_exists,
)

from flask import (
    abort,
    jsonify,
    request
)

from flask_smorest import Blueprint

from dservercore import (
    AuthenticationError,
    sql_db
)
from dservercore.sql_models import (
    Dataset,
)
from dservercore.utils import (
    generate_dataset_info,
    register_dataset,
)

from .config import Config, CONFIG_SECRETS_TO_OBFUSCATE


AFFIRMATIVE_EXPRESSIONS = ['true', '1', 'y', 'yes', 'on']
UUID_REGEX_PATTERN = '[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}'
UUID_REGEX = re.compile(UUID_REGEX_PATTERN, re.IGNORECASE)

logger = logging.getLogger(__name__)


def _log_nested(log_func, dct):
    for l in json.dumps(dct, indent=2, default=str).splitlines():
        log_func(l)


def filter_ips(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        # Check if header has been rewritten by reverse proxy and look into HTTP_X_REAL_IP first

        real_ip = request.headers.get('HTTP_X_REAL_IP', None)

        if real_ip is None:
            logger.debug("request.headers does not contain field HTTP_X_REAL_IP, try X-Forwarded-For")
            real_ip = request.headers.get('X-Forwarded-For', None)

        if real_ip is None:
            logger.debug("request.headers does not contain field X-Forwarded-For, try X-Real-IP")
            real_ip = request.headers.get('X-Real-IP', None)

        if real_ip is None:
            logger.debug("request.headers does not contain field HTTP_X_REAL_IP.")
            real_ip = request.remote_addr
            logger.debug("Instead use request.remote_addr '%s%'.", real_ip)

        ip = ipaddress.ip_address(real_ip)
        logger.info("Accessed from %s", ip)
        if ip in Config.ALLOW_ACCESS_FROM:
            return f(*args, **kwargs)
        else:
            return abort(403)

    return wrapped


def _parse_obj_key(key):
    # Just looking at the end of the key is a bit risky, you might find
    # anything below the data prefix, including another wrapped dataset, hence:
    # TODO: check for relative position below top-level
    components = key.split('/')
    if len(components) > 1:
        if components[-2] in ['data', 'tags', 'annotations']:
            # The UUID is the component before 'data'
            uuid = components[-3]
            kind = components[-2]
        else:
            # No data entry, the UUID is the second to last component
            uuid = components[-2]
            kind = components[-1]
    else:
        if components[0].startswith('dtool-'):
            # This is the registration key
            uuid = components[0][6:]
            kind = '__REGISTRATION_KEY__'
        else:
            kind = None
            uuid = None

    return uuid, kind


def _reconstruct_uri(base_uri, object_key):
    """Reconstruct dataset URI on S3 bucket from bucket name and object key."""
    # The expected structure of an object key (without preceding bucket name)
    # is either
    #   dtool-{UUID}
    # for the top-level "link" object or
    #   [{arbitrary_prefix}/]{UUID}[/{other_arbitrary_suffix}]
    # There are now several to infer the URI of a dataset.
    # The important key point is that all dtool-processible URIs
    # point to the bucket top level, no matter whether the actual dataset
    # resides at top-level as well or below some other prefix. This means
    #   s3://test-bucket/49f0bf41-471b-4781-855e-161fe81ffb0d
    # may point to a dataset actually residing at
    #   s3://test-bucket/49f0bf41-471b-4781-855e-161fe81ffb0d
    # or below some arbitrary prefix, i.e.
    #   s3://test-bucket/u/test-user/49f0bf41-471b-4781-855e-161fe81ffb0d
    # resolved by the content of the top-level "link" object
    #   s3://test-bucket/dtool-49f0bf41-471b-4781-855e-161fe81ffb0d
    # Seemingly, the straight forward approach would be to only evaluate
    # top-level dtool-{UUID} objects and infer the URI as
    #   s3://{BUCKET_NAME}/{UUID}
    # As we must not make any assumptions on the order of object creation,
    # a notification about a new dtool-{UUID} does not mean the availability
    # of a healthy dataset fit for registration. Beyond that, updates to
    # a dataset may not touch the dtool-{UUID} object. Instead, we try to infer
    # the UUID of the containing dataset for every object notification, check
    # whether a dataset has been registered already with the according
    # combination of base URI and UUID, retrieve the correct dataset URI from
    # the index in this case, or just construct it by concatenating base URI
    # and UUID as
    #   {BASE_URI}/{UUID}
    # Note that the mapping (BASE_URI, UUID) <-> URI is only bijective
    # for the s3 storage broker. It cannot be generalized to other storage.
    # We need to find the dataset UUID in the obejct key. A viable approach
    # is to just look for the first valid v4 UUID in the string. This would
    # conflict with a prefix that contains a v4 UUID as well.

    uuid_match = UUID_REGEX.search(object_key)
    if uuid_match is None:
        # This should not happen, all s3 objects created via dtool
        # must have a valid UUID within its object key.
        raise ValueError("The object key %s does not contain any valid UUID.", object_key)

    uuid = uuid_match.group(0)
    logger.debug("Extracted UUID '%s' from object key '%s'.", uuid, object_key)

    # check whether this (BASE_URI, UUID) combination has been registered before
    uri = _retrieve_uri(base_uri, uuid)

    if uri is None:
        # instead of using the dtoolcore._generate_uri proxy, we explicitly
        # use the dtool_s3.storagebroker.S3StorageBroker.generate_uri class
        # method as we know the name does not play a role here.
        # uri = dtool_s3.storagebroker.S3StorageBroker.generate_uri(
        #     name='dummy', uuid=uuid, base_uri=base_uri)
        # instead of the explicit use of dtool_s3 above, we revert to the
        # following
        return dtoolcore._generate_uri({'uuid': uuid, 'name': uuid}, base_uri)
        # just to make our current tests pass.
        # TODO: kick out dtoolcore._generate_uri once we have proper S3-based tests

        logger.debug(("Dataset has not been registered yet, "
                      "reconstructed URI '%s' from base URI '%s' and UUID '%s'."),
                     uri, base_uri, uuid)
    else:
        logger.debug("Dataset registered before under URI '%s'.", uri)

    return uri


def _retrieve_uri(base_uri, uuid):
    """Retrieve URI(s) from database given as base URI and an UUID"""
    if not base_uri_exists(base_uri):
        raise(ValidationError(
            "Base URI is not registered: {}".format(base_uri)
        ))

    # Query database to construct the respective URI. We cannot just
    # concatenate base URI and UUID since the URI may depend on the name of
    # the dataset which we do not have.
    uris = []
    query_result = sql_db.session.query(Dataset, BaseURI)  \
        .filter(Dataset.uuid == uuid)  \
        .filter(BaseURI.id == Dataset.base_uri_id)  \
        .filter(BaseURI.base_uri == base_uri)
    logger.debug("Query result:")
    _log_nested(logger.debug, query_result)

    for dataset, base_uri in query_result:
        # this general treatment makes sense for arbitrary storage brokers, but
        # for the current (2022-02) implementation of the s3 broker, the actual
        # dataset name is irrelevant for the URI. Furthermore. there should
        # always be only one entry for a particular (BASE_URI, UUID) tuple
        # on an s3 bucket.
        return dtoolcore._generate_uri(
            {'uuid': dataset.uuid, 'name': dataset.name}, base_uri.base_uri)

    return None


# event names from https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html
OBJECT_CREATED_EVENT_NAMES = [
    's3:ObjectCreated:Put',
    's3:ObjectCreated:Post',
    's3:ObjectCreated:Copy',
    's3:ObjectCreated:CompleteMultipartUpload',
    'ObjectCreated:Put',  # NetApp Storage GRID via SNS endpoint uses event names without s3 prefix
    'ObjectCreated:Post',
    'ObjectCreated:Copy',
    'ObjectCreated:CompleteMultipartUpload'
]


OBJECT_REMOVED_EVENT_NAMES = [
    's3:ObjectRemoved:Delete',
    's3:ObjectRemoved:DeleteMarkerCreated',
    'ObjectRemoved:Delete',  # NetApp Storage GRID via SNS endpoint uses event names without s3 prefix
    'ObjectRemoved:DeleteMarkerCreated'
]

# expected event structure from
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html
# {
#    "Records":[
#       {
#          "eventVersion":"2.2",
#          "eventSource":"aws:s3",
#          "awsRegion":"us-west-2",
#          "eventTime":"The time, in ISO-8601 format, for example, 1970-01-01T00:00:00.000Z, when Amazon S3 finished processing the request",
#          "eventName":"event-type",
#          "userIdentity":{
#             "principalId":"Amazon-customer-ID-of-the-user-who-caused-the-event"
#          },
#          "requestParameters":{
#             "sourceIPAddress":"ip-address-where-request-came-from"
#          },
#          "responseElements":{
#             "x-amz-request-id":"Amazon S3 generated request ID",
#             "x-amz-id-2":"Amazon S3 host that processed the request"
#          },
#          "s3":{
#             "s3SchemaVersion":"1.0",
#             "configurationId":"ID found in the bucket notification configuration",
#             "bucket":{
#                "name":"bucket-name",
#                "ownerIdentity":{
#                   "principalId":"Amazon-customer-ID-of-the-bucket-owner"
#                },
#                "arn":"bucket-ARN"
#             },
#             "object":{
#                "key":"object-key",
#                "size":"object-size in bytes",
#                "eTag":"object eTag",
#                "versionId":"object version if bucket is versioning-enabled, otherwise null",
#                "sequencer": "a string representation of a hexadecimal value used to determine event sequence, only used with PUTs and DELETEs"
#             }
#          },
#          "glacierEventData": {
#             "restoreEventData": {
#                "lifecycleRestorationExpiryTime": "The time, in ISO-8601 format, for example, 1970-01-01T00:00:00.000Z, of Restore Expiry",
#                "lifecycleRestoreStorageClass": "Source storage class for restore"
#             }
#          }
#       }
#    ]
# }
#
# if NetApp storage grid is configured for an SNS endpoint, it does not
# directly submit content of type 'application/json', but instead
# 'application/x-www-form-urlencoded'. request.form has the structure
# {
#   "server": [
#   "Action": "Publish",
#   "Message": "{...}",
#   "TopicArn": "urn:test:sns:test:test:test",
#     "0.0.0.0",
#   "Version": "2010-03-31"
# }
#
# and includes an S3 event notification of above standard within 'Message'
#
# {
#   "Records": [
#     {
#       "eventVersion": "2.0",
#       "eventSource": "sgws:s3",
#       "eventTime": "2022-03-09T12:30:21Z",
#       "eventName": "ObjectCreated:Put",
#       "userIdentity": {
#         "principalId": "80888526281258163395"
#       },
#       "requestParameters": {
#         "sourceIPAddress": "132.230.239.200"
#       },
#       "responseElements": {
#         "x-amz-request-id": "1646829021003401"
#       },
#       "s3": {
#         "s3SchemaVersion": "1.0",
#         "configurationId": "Object created test",
#         "bucket": {
#           "name": "frct-livmats",
#           "ownerIdentity": {
#             "principalId": "80888526281258163395"
#           },
#           "arn": "urn:sgws:s3:::frct-livmats"
#         },
#         "object": {
#           "key": "u/jh1130/481b1bc4-f867-4580-b5d3-28fd7e64a107/dtool",
#           "size": 233,
#           "eTag": "e999ae313285a5313c3fcf4ff13bd3ca",
#           "sequencer": "16DAB6450E18CA14"
#         }
#       }
#     }
#   ]
# }


def _process_object_created(base_uri, object_key):
    """Try to register new or update existing dataset entry if object created."""

    uuid, kind = _parse_obj_key(object_key)

    # We also need to update the database if the metadata has changed.
    # Here, we just brute-force attempt registration at every object write
    # as notifications may appear in arbitrary order. Another option might
    # be to look out for either the README.yml or the the 'dtool' object
    # of the respective UUID that finalizes creation of a dataset.
    dataset_uri = _reconstruct_uri(base_uri, object_key)

    if dataset_uri is not None:
        try:
            dataset = dtoolcore.DataSet.from_uri(dataset_uri)
            dataset_info = generate_dataset_info(dataset, base_uri)
            register_dataset(dataset_info)
        except dtoolcore.DtoolCoreTypeError:
            # DtoolCoreTypeError is raised if this is not a dataset yet, i.e.
            # if the dataset has only partially been copied. There will be
            # another notification once everything is final. We simply
            # ignore this.
            logger.debug('DtoolCoreTypeError raised for dataset '
                         'with URI %s', dataset_uri)
            pass
    else:
        logger.info(("Creation of '%s' within '%s' does not constitute the "
                     "creation of a complete dataset or update of its metadata. "
                     "Ignored."), object_key, base_uri)


def _process_object_removed(base_uri, object_key):
    """Notify the lookup server about deletion of an object."""
    # The only information that we get is the URL. We need to convert the URL
    # into the respective UUID of the dataset.

    # only delete dataset from index if the `dtool` object is deleted

    if object_key.endswith('/dtool'):  # somewhat dangerous if another item is named dtool
        uri = _reconstruct_uri(base_uri, object_key)
        uuid, kind = _parse_obj_key(object_key)
        assert kind == 'dtool'

        logger.info('Deleting dataset with URI {}'.format(uri))

        # Delete datasets with this URI
        sql_db.session.query(Dataset) \
            .filter(Dataset.uri == uri) \
            .delete()
        sql_db.session.commit()


def _process_event(event_name, event_data):
    """"Delegate S3 notification event processing o correct handler."""
    # TODO: consider s3SchemaVersion

    if event_name in [*OBJECT_CREATED_EVENT_NAMES, *OBJECT_REMOVED_EVENT_NAMES]:
        try:
            bucket_name = event_data['bucket']['name']
        except KeyError as exc:
            logger.error(str(exc))
            abort(400)

        try:
            object_key = event_data['object']['key']
        except KeyError as exc:
            logger.error(str(exc))
            abort(400)

        # object keys are %xx-escaped, bucket names as well?
        logger.info("Received notification for raw bucket name '%s' and raw object key '%s'",
                    bucket_name, object_key)
        bucket_name = urllib.parse.unquote(bucket_name, encoding='utf-8', errors='replace')
        object_key = urllib.parse.unquote(object_key, encoding='utf-8', errors='replace')
        logger.info(
            "Received notification for de-escaped bucket name '%s' and de-escaped object key '%s'",
            bucket_name, object_key)

        # TODO: the same bucket name may exist at different locations wit different base URIS
        if bucket_name not in Config.BUCKET_TO_BASE_URI:
            logger.error("No base URI configured for bucket '%s'.", bucket_name)
            abort(400)

        base_uri = Config.BUCKET_TO_BASE_URI[bucket_name]

        if event_name in OBJECT_CREATED_EVENT_NAMES:
            logger.info("Object '%s' created within '%s'", object_key, base_uri)
            _process_object_created(base_uri, object_key)
        elif event_name in OBJECT_REMOVED_EVENT_NAMES:
            logger.info("Object '%s' removed from '%s'", object_key, base_uri)
            _process_object_removed(base_uri, object_key)

    else:
        logger.info("Event '%s' ignored.", event_name)


webhook_bp = Blueprint("webhook", __name__, url_prefix="/webhook")


# wildcard route,
# see https://flask.palletsprojects.com/en/2.0.x/patterns/singlepageapplications/
# strict_slashes=False matches '/notify' and '/notify/'
@webhook_bp.route('/notify', defaults={'path': ''}, methods=['POST'], strict_slashes=False)
@webhook_bp.route('/notify/<path:path>', methods=['POST'])
@webhook_bp.response(200)
@filter_ips
def notify(path):
    """Notify the lookup server about creation, modification or deletion of a
    dataset."""

    json_content = None

    if request.content_type is None:
        error_msg = "No content in request."
        logger.error(error_msg)
        abort(400, description=error_msg)

    # special treatment for form data as submitted by NetApp Storage GRID
    if request.content_type.startswith('application/x-www-form-urlencoded'):
        logger.debug("Received 'application/x-www-form-urlencoded' content.")
        form = request.form
        logger.debug("Form:")
        _log_nested(logger.debug, form)
        if 'Message' in form:
            logger.debug("Try to parse 'Message' field of form as JSON.")
            try:
                json_content = json.loads(form['Message'])
                logger.debug("Succeeded to parse 'Message' field of form as JSON.")
            except:
                logger.warning("Failed to parse 'Message' field of form '%s' as JSON.", form['Message'])
    else: # general treatment, usually for 'application/json'
        json_content = request.get_json()

    logger.debug("Request JSON:")
    _log_nested(logger.debug, json_content)
    if json_content is None:
        logger.error("No JSON attached.")
        # health check: NetApp Storage GRID performs a health check post request,
        # but attaches content of type 'application/x-www-form-urlencoded', i.e.
        #  Action=Publish&Message=StorageGRID+Test+Message&TopicArn=urn%3Atest%3Asns%3Atest%3Atest%3Atest&Version=2010-03-31
        return

    records = json_content.get('Records')
    if not isinstance(records, list) or len(records) == 0:
        error_msg = "No 'Records' in notification."
        logger.error(error_msg)
        abort(400, description=error_msg)

    logger.debug("Records:")
    _log_nested(logger.debug, records)

    try:
        event_name = records[0]['eventName']
    except (KeyError, TypeError):
        error_msg = "No 'eventName' in 'Records'."
        logger.error(error_msg)
        abort(400, description=error_msg)

    try:
        event_data = records[0]['s3']
    except (KeyError, TypeError):
        error_msg = "No 's3' in 'Records'."
        logger.error(error_msg)
        abort(400, description=error_msg)

    return jsonify(_process_event(event_name, event_data))


class NotificationExtension(ExtensionABC):

    def init_app(self, app):
        pass

    def register_dataset(self, dataset_info):
        pass

    def get_config(self):
        """Return initial Config object, available app-instance independent."""
        return Config

    def get_config_secrets_to_obfuscate(self):
        """Return config secrets never to be exposed clear text."""
        return CONFIG_SECRETS_TO_OBFUSCATE

    def get_blueprint(self):
        return webhook_bp