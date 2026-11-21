"""SigV4 signatures must be identical to AWS's own implementation (botocore)."""
import datetime as dt

import pytest
import requests

from apisynth.auth import SigV4Auth

botocore = pytest.importorskip("botocore")
from botocore.auth import SigV4Auth as BotoSigV4  # noqa: E402
from botocore.awsrequest import AWSRequest  # noqa: E402
from botocore.credentials import Credentials as BotoCreds  # noqa: E402

KEY, SECRET = "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


@pytest.mark.parametrize("method,url,body,headers,token,region", [
    ("GET", "https://abc123.execute-api.us-east-1.amazonaws.com/prod/pets", None, {}, None, "us-east-1"),
    ("GET", "https://abc123.execute-api.us-east-1.amazonaws.com/prod/pets?type=dog&limit=10&a=%20x&a=b", None, {}, None, "us-east-1"),
    ("POST", "https://abc123.execute-api.eu-west-1.amazonaws.com/v1/orders", b'{"qty": 2, "name": "x y"}',
     {"Content-Type": "application/json"}, None, "eu-west-1"),
    ("PUT", "https://api.example.com:8443/items/a%20b/%C3%BC", b"hi", {"Content-Type": "text/plain"}, "SESSIONTOKEN", "us-east-1"),
    ("DELETE", "https://search-x.us-west-2.es.amazonaws.com/idx/_doc/1?refresh=true", None, {}, None, "us-west-2"),
])
def test_matches_botocore(method, url, body, headers, token, region):
    areq = AWSRequest(method=method, url=url, data=body or b"", headers=dict(headers))
    BotoSigV4(BotoCreds(KEY, SECRET, token), "execute-api", region).add_auth(areq)
    when = dt.datetime.strptime(areq.headers["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    req = requests.Request(method, url, data=body, headers=dict(headers)).prepare()
    SigV4Auth(KEY, SECRET, region, "execute-api", token, now=when)(req)
    assert req.headers["Authorization"].split("Signature=")[1] == areq.headers["Authorization"].split("Signature=")[1]
    assert req.headers["Authorization"].split("SignedHeaders=")[1].split(",")[0] == \
        areq.headers["Authorization"].split("SignedHeaders=")[1].split(",")[0]
