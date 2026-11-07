"""Exercise the real urllib HTTP/redirect stack without sockets or real secrets."""
import base64
from email.message import Message
from io import BytesIO
import json
import urllib.request
from urllib.response import addinfourl

import pytest

from tools.elastic_adapter import ElasticClient, ElasticHTTPError


API_KEY = "INERT-TEST-API-KEY"
PASSWORD = "INERT-TEST-PASSWORD"
BASIC = "Basic " + base64.b64encode(f"review-user:{PASSWORD}".encode()).decode()
REDIRECT_BODY = b"INERT-REDIRECT-RESPONSE-BODY"


@pytest.fixture
def transport(monkeypatch):
    """Replace only HTTP I/O; urllib still performs headers, errors and redirects."""
    calls, responses = [], []

    def respond(handler, request):
        calls.append({
            "url": request.full_url,
            "method": request.get_method(),
            "headers": {key.lower(): value for key, value in request.header_items()},
            "body": request.data,
            "timeout": request.timeout,
        })
        assert responses, "Unexpected HTTP request (no network is permitted in this test)"
        code, headers, body = responses.pop(0)
        message = Message()
        for key, value in headers.items():
            message[key] = value
        response = addinfourl(BytesIO(body), message, request.full_url, code)
        response.msg = "synthetic HTTP response"
        return response

    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", respond)
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", respond)
    return calls, responses


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("target", [
    "/canonical/_mapping?location=INERT-LOCATION",
    "https://other.example/collect?location=INERT-LOCATION",
    "http://other.example/collect?location=INERT-LOCATION",
], ids=["same-origin", "foreign-https", "https-downgrade"])
def test_redirect_is_rejected_before_any_second_request(transport, status, target):
    calls, responses = transport
    responses.extend([
        (status, {"Location": target}, REDIRECT_BODY),
        (200, {}, b'{"unexpected_redirect_success":true}'),
    ])
    client = ElasticClient("https://elastic.example", api_key=API_KEY)

    with pytest.raises(ElasticHTTPError) as error:
        client.request("GET", "/_mapping")

    assert error.value.status == status
    assert len(calls) == 1
    assert calls[0]["url"] == "https://elastic.example/_mapping"
    assert calls[0]["headers"]["authorization"] == "ApiKey " + API_KEY
    assert len(responses) == 1  # The target was never requested.
    for private_value in (API_KEY, target, "INERT-LOCATION", REDIRECT_BODY.decode()):
        assert private_value not in str(error.value)


@pytest.mark.parametrize("status,location", [
    (301, "https://[INERT-PRIVATE-LOCATION]/collect"),
    (302, "https://[INERT-PRIVATE-LOCATION]/collect"),
    (303, "https://[INERT-PRIVATE-LOCATION]/collect"),
    (307, "https://[INERT-PRIVATE-LOCATION]/collect"),
    (308, "https://[INERT-PRIVATE-LOCATION]/collect"),
    (302, "//other.example/INERT-PRIVATE-LOCATION"),
    (302, ""),
    (302, None),
], ids=[
    "malformed-301", "malformed-302", "malformed-303", "malformed-307", "malformed-308",
    "scheme-relative", "empty-location", "missing-location",
])
def test_redirect_never_parses_or_echoes_the_location(transport, status, location):
    calls, responses = transport
    headers = {} if location is None else {"Location": location}
    responses.append((status, headers, REDIRECT_BODY))

    with pytest.raises(ElasticHTTPError) as error:
        ElasticClient("https://elastic.example", api_key=API_KEY).request("GET", "/_mapping")

    assert error.value.status == status
    assert len(calls) == 1
    assert "INERT-PRIVATE-LOCATION" not in str(error.value)
    assert REDIRECT_BODY.decode() not in str(error.value)
    assert API_KEY not in str(error.value)


@pytest.mark.parametrize("auth,expected_authorization", [
    ({"api_key": API_KEY}, "ApiKey " + API_KEY),
    ({"username": "review-user", "password": PASSWORD}, BASIC),
    ({}, None),
], ids=["api-key", "basic", "anonymous"])
@pytest.mark.parametrize("method,body,ndjson", [
    ("GET", None, False),
    ("POST", {"query": {"term": {"event.id": "INERT-EVENT"}}}, False),
    ("POST", '{"create":{"_id":"INERT-EVENT"}}\n{"value":"INERT-PAYLOAD"}\n', True),
], ids=["get", "post-json", "post-ndjson"])
def test_redirect_rejection_covers_auth_modes_and_request_bodies(
        transport, auth, expected_authorization, method, body, ndjson):
    calls, responses = transport
    target = "https://other.example/redirect-target"
    responses.extend([
        (303, {"Location": target}, REDIRECT_BODY),
        (200, {}, b'{"unexpected_redirect_success":true}'),
    ])
    client = ElasticClient("https://elastic.example", **auth)

    with pytest.raises(ElasticHTTPError) as error:
        client.request(method, "/_search", body, ndjson=ndjson)

    assert error.value.status == 303
    assert len(calls) == 1
    assert calls[0]["method"] == method
    assert calls[0]["headers"].get("authorization") == expected_authorization
    for private_value in (API_KEY, PASSWORD, BASIC, target, REDIRECT_BODY.decode()):
        assert private_value not in str(error.value)
    assert len(responses) == 1


@pytest.mark.parametrize("method,body,ndjson", [
    ("GET", None, False),
    ("POST", {"query": {"match_all": {}}}, False),
    ("PUT", {"settings": {"number_of_shards": 1}}, False),
    ("DELETE", {"id": "INERT-PIT"}, False),
    ("POST", '{"create":{"_id":"INERT-ID"}}\n{"value":1}\n', True),
], ids=["get", "post-json", "put-json", "delete-json", "post-ndjson"])
def test_direct_requests_preserve_method_auth_payload_timeout_and_json(
        transport, method, body, ndjson):
    calls, responses = transport
    responses.append((200, {}, b'{"acknowledged":true,"value":17}'))
    client = ElasticClient("https://elastic.example", api_key=API_KEY, timeout=12.5)

    assert client.request(method, "/index", body, ndjson=ndjson) == {
        "acknowledged": True, "value": 17,
    }
    assert len(calls) == 1
    call = calls[0]
    assert call["url"] == "https://elastic.example/index"
    assert call["method"] == method
    assert call["headers"]["authorization"] == "ApiKey " + API_KEY
    assert call["timeout"] == 12.5
    if ndjson:
        assert call["headers"]["content-type"] == "application/x-ndjson"
        assert call["body"] == body.encode("utf-8")
    else:
        assert call["headers"]["content-type"] == "application/json"
        assert (json.loads(call["body"]) if body is not None else call["body"]) == body
    assert responses == []


@pytest.mark.parametrize("status", [401, 409])
def test_nonredirect_http_errors_keep_status_without_response_details(transport, status):
    calls, responses = transport
    responses.append((status, {}, b'{"error":"INERT-PRIVATE-RESPONSE"}'))
    client = ElasticClient("https://elastic.example", username="review-user", password=PASSWORD)

    with pytest.raises(ElasticHTTPError) as error:
        client.request("GET", "/_mapping")

    assert error.value.status == status
    assert len(calls) == 1
    assert calls[0]["headers"]["authorization"] == BASIC
    assert "INERT-PRIVATE-RESPONSE" not in str(error.value)
    assert PASSWORD not in str(error.value)
    assert BASIC not in str(error.value)


def test_client_does_not_use_or_replace_an_application_global_opener(transport, monkeypatch):
    class ApplicationOpener:
        def open(self, *args, **kwargs):
            pytest.fail("Elastic traffic reached the application's global opener")

    application_opener = ApplicationOpener()
    monkeypatch.setattr(urllib.request, "_opener", application_opener)
    calls, responses = transport
    responses.append((200, {}, b'{"ok":true}'))

    assert ElasticClient("https://elastic.example").request("GET", "/") == {"ok": True}
    assert len(calls) == 1
    assert urllib.request._opener is application_opener
