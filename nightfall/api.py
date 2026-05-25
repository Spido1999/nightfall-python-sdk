"""nightfall/api.py — patched version
Changes vs upstream:
  - Add _DEFAULT_TIMEOUT = (5, 30) constant; pass to all HTTP calls
  - Fix self.session.headers.update() instead of assignment (preserves requests defaults)
  - Add timeout parameter to __init__
  - Validate empty texts list in scan_text
  - Guard validate_webhook against non-integer timestamp
"""
from datetime import datetime, timedelta
import hmac
import hashlib
import logging
import os
from typing import List, Tuple, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from nightfall.alerts import AlertConfig
from nightfall.detection_rules import DetectionRule, RedactionConfig
from nightfall.exceptions import NightfallUserError, NightfallSystemError
from nightfall.findings import Finding


# Default timeout: (connect_timeout_seconds, read_timeout_seconds)
# Prevents the SDK from hanging indefinitely on network issues.
_DEFAULT_TIMEOUT: Tuple[int, int] = (5, 30)


class Nightfall:
    PLATFORM_URL = "https://api.nightfall.ai"
    TEXT_SCAN_ENDPOINT_V3 = PLATFORM_URL + "/v3/scan"
    FILE_SCAN_INITIALIZE_ENDPOINT = PLATFORM_URL + "/v3/upload"
    FILE_SCAN_UPLOAD_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}"
    FILE_SCAN_COMPLETE_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}/finish"
    FILE_SCAN_SCAN_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}/scan"

    def __init__(self, key: Optional[str] = None, signing_secret: Optional[str] = None,
                 timeout: Tuple[int, int] = _DEFAULT_TIMEOUT):
        """Instantiate a new Nightfall object.

        :param key: Your Nightfall API key.
            If None it will be read from the environment variable NIGHTFALL_API_KEY.
        :type key: str or None
        :param signing_secret: Your Nightfall signing secret used for webhook validation.
        :type signing_secret: str or None
        :param timeout: HTTP request timeout as (connect_seconds, read_seconds).
            Defaults to (5, 30). Pass None to disable timeouts.
        :type timeout: tuple or None
        """
        if key:
            self.key = key
        else:
            self.key = os.getenv("NIGHTFALL_API_KEY")

        if not self.key:
            raise NightfallUserError(
                "need an API key either in constructor or in NIGHTFALL_API_KEY environment var",
                40001,
            )

        self.signing_secret = signing_secret
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        retries = Retry(total=5, allowed_methods=Retry.DEFAULT_ALLOWED_METHODS | {"PATCH", "POST"})
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        # Use update() to preserve requests default session headers
        # (Accept-Encoding, Accept, Connection) rather than replacing the dict.
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "nightfall-python-sdk/1.4.1",
            "Authorization": f"Bearer {self.key}",
        })

    def scan_text(self, texts: List[str], policy_uuids: List[str] = None,
                  detection_rules: Optional[List[DetectionRule]] = None,
                  detection_rule_uuids: Optional[List[str]] = None,
                  context_bytes: Optional[int] = None,
                  default_redaction_config: Optional[RedactionConfig] = None,
                  alert_config: Optional[AlertConfig] = None) -> \
            Tuple[List[List[Finding]], List[str]]:
        """Scan text with Nightfall.

        This method takes the specified config and then makes
        one or more requests to the Nightfall API for scanning.

        A caller must provide exactly one of the following:
            * a non-empty policy_uuids list (current maximum supported length = 1)
            * at least one of detection_rule_uuids or detection_rules

        :param texts: List of strings to scan.
        :type texts: List[str]
        :param policy_uuids: List of policy UUIDs to scan each text with.
        :type policy_uuids: List[str] or None
        :param detection_rules: List of detection rules to scan each text with.
        :type detection_rules: List[DetectionRule] or None
        :param detection_rule_uuids: List of detection rule UUIDs to scan each text with.
        :type detection_rule_uuids: List[str] or None
        :param context_bytes: The number of bytes of context to return with findings.
        :type context_bytes: int or None
        :param default_redaction_config: Default redaction configuration.
        :type default_redaction_config: RedactionConfig or None
        :param alert_config: External alert destinations.
        :type alert_config: AlertConfig or None
        :returns: list of findings, list of redacted input texts
        """
        if not texts:
            raise NightfallUserError("texts list must not be empty", 40001)

        if not policy_uuids and not detection_rule_uuids and not detection_rules:
            raise NightfallUserError(
                "at least one of policy_uuids, detection_rule_uuids, or detection_rules is required",
                40001,
            )

        policy = {}
        if detection_rule_uuids:
            policy["detectionRuleUUIDs"] = detection_rule_uuids
        if detection_rules:
            policy["detectionRules"] = [d.as_dict() for d in detection_rules]
        if context_bytes:
            policy["contextBytes"] = context_bytes
        if default_redaction_config:
            policy["defaultRedactionConfig"] = default_redaction_config.as_dict()
        if alert_config:
            policy["alertConfig"] = alert_config.as_dict()

        request_body = {"payload": texts}
        if policy:
            request_body["policy"] = policy
        if policy_uuids:
            request_body["policyUUIDs"] = policy_uuids
        response = self._scan_text_v3(request_body)

        _validate_response(response, 200)

        parsed_response = response.json()
        findings = [
            [Finding.from_dict(f) for f in item_findings]
            for item_findings in parsed_response["findings"]
        ]
        return findings, parsed_response.get("redactedPayload")

    def _scan_text_v3(self, data: dict):
        response = self.session.post(
            url=self.TEXT_SCAN_ENDPOINT_V3,
            json=data,
            timeout=self.timeout,
        )
        self.logger.debug(f"HTTP Request URL: {response.request.url}")
        self.logger.debug(f"HTTP Request Body: {response.request.body}")
        self.logger.debug(f"HTTP Request Headers: {response.request.headers}")
        self.logger.debug(f"HTTP Status Code: {response.status_code}")
        self.logger.debug(f"HTTP Response Headers: {response.headers}")
        self.logger.debug(f"HTTP Response Text: {response.text}")
        return response

    # File Scan

    def scan_file(self, location: str, webhook_url: Optional[str] = None,
                  policy_uuid: Optional[str] = None,
                  detection_rules: Optional[List[DetectionRule]] = None,
                  detection_rule_uuids: Optional[List[str]] = None,
                  request_metadata: Optional[str] = None,
                  alert_config: Optional[AlertConfig] = None) -> Tuple[str, str]:
        """Scan file with Nightfall.

        At least one of policy_uuid, detection_rule_uuids or detection_rules is required.

        :param location: location of file to scan.
        :param webhook_url: webhook endpoint which will receive the results of the scan.
        :param policy_uuid: policy UUID.
        :param detection_rules: list of detection rules.
        :param detection_rule_uuids: list of detection rule UUIDs.
        :param request_metadata: additional metadata returned with the webhook response.
        :param alert_config: external alert destinations.
        :returns: (scan_id, message)
        """
        if not policy_uuid and not detection_rule_uuids and not detection_rules:
            raise NightfallUserError(
                "at least one of policy_uuid, detection_rule_uuids or detection_rules required",
                40001,
            )

        response = self._file_scan_initialize(location)
        _validate_response(response, 200)
        result = response.json()
        session_id, chunk_size = result["id"], result["chunkSize"]

        uploaded = self._file_scan_upload(session_id, location, chunk_size)
        if not uploaded:
            raise NightfallSystemError("File upload failed", 50000)

        response = self._file_scan_finalize(session_id)
        _validate_response(response, 200)

        response = self._file_scan_scan(
            session_id,
            detection_rules=detection_rules,
            detection_rule_uuids=detection_rule_uuids,
            webhook_url=webhook_url,
            policy_uuid=policy_uuid,
            request_metadata=request_metadata,
            alert_config=alert_config,
        )
        _validate_response(response, 200)
        parsed_response = response.json()
        return parsed_response["id"], parsed_response["message"]

    def _file_scan_initialize(self, location: str):
        data = {"fileSizeBytes": os.path.getsize(location)}
        return self.session.post(
            url=self.FILE_SCAN_INITIALIZE_ENDPOINT,
            json=data,
            timeout=self.timeout,
        )

    def _file_scan_upload(self, session_id: str, location: str, chunk_size: int):
        def read_chunks(fp, chunk_size):
            ix = 0
            while True:
                data = fp.read(chunk_size)
                if not data:
                    break
                yield ix, data
                ix = ix + 1

        def upload_chunk(id, data, headers):
            return self.session.patch(
                url=self.FILE_SCAN_UPLOAD_ENDPOINT.format(id),
                data=data,
                headers=headers,
                timeout=self.timeout,
            )

        with open(location, "rb") as fp:
            for ix, piece in read_chunks(fp, chunk_size):
                headers = {"X-UPLOAD-OFFSET": str(ix * chunk_size)}
                response = upload_chunk(session_id, piece, headers)
                _validate_response(response, 204)

        return True

    def _file_scan_finalize(self, session_id: str):
        return self.session.post(
            url=self.FILE_SCAN_COMPLETE_ENDPOINT.format(session_id),
            timeout=self.timeout,
        )

    def _file_scan_scan(self, session_id: str,
                        detection_rules: Optional[List[DetectionRule]] = None,
                        detection_rule_uuids: Optional[List[str]] = None,
                        webhook_url: Optional[str] = None,
                        policy_uuid: Optional[str] = None,
                        request_metadata: Optional[str] = None,
                        alert_config: Optional[AlertConfig] = None) -> requests.Response:
        if policy_uuid:
            data = {"policyUUID": policy_uuid}
        else:
            data = {"policy": {}}
            if webhook_url:
                data["policy"]["webhookURL"] = webhook_url
            if detection_rule_uuids:
                data["policy"]["detectionRuleUUIDs"] = detection_rule_uuids
            if detection_rules:
                data["policy"]["detectionRules"] = [d.as_dict() for d in detection_rules]
            if alert_config:
                data["policy"]["alertConfig"] = alert_config.as_dict()

        if request_metadata:
            data["requestMetadata"] = request_metadata

        return self.session.post(
            url=self.FILE_SCAN_SCAN_ENDPOINT.format(session_id),
            json=data,
            timeout=self.timeout,
        )

    def validate_webhook(self, request_signature: str, request_timestamp: str,
                         request_data: str) -> bool:
        """Validate the integrity of webhook requests coming from Nightfall.

        :param request_signature: value of X-Nightfall-Signature header
        :param request_timestamp: value of X-Nightfall-Timestamp header
        :param request_data: request body as a unicode string
        :returns: validation status boolean
        """
        try:
            ts_int = int(request_timestamp)
        except (TypeError, ValueError):
            return False

        now = datetime.now()
        request_datetime = datetime.fromtimestamp(ts_int)
        if request_datetime < now - timedelta(minutes=5) or request_datetime > now:
            return False
        computed_signature = hmac.new(
            self.signing_secret.encode(),
            msg=f"{request_timestamp}:{request_data}".encode(),
            digestmod=hashlib.sha256,
        ).hexdigest().lower()

        if computed_signature != request_signature:
            return False
        return True


# Utility
def _validate_response(response: requests.Response, expected_status_code: int):
    if response.status_code == expected_status_code:
        return
    response_json = response.json()
    error_code = response_json.get("code", None)
    if error_code is None:
        raise NightfallSystemError(response.text, 50000)
    if error_code < 40000 or error_code >= 50000:
        raise NightfallSystemError(response.text, error_code)
    else:
        raise NightfallUserError(response.text, error_code)
