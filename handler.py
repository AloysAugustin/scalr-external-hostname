#!/usr/bin/env python

import base64
import binascii
from datetime import datetime
import hashlib
import hmac
import json
import logging
import os
import sys
import urllib
import urlparse

import dateutil.parser
from flask import Flask
from flask import request
from flask import abort
import pytz
import requests
import requests.auth
import requests.exceptions
import yaml

SCALR_URL = ''
SCALR_API_KEY = ''
SCALR_API_SECRET = ''
SCALR_SIGNING_KEY = ''
GV_NAME = ''

def loadSettings(path):
    with open(path) as f:
        data = yaml.load(f.read())
        for key in data:
            if key in globals():
                globals()[key] = data[key]

app = Flask(__name__)


@app.route("/", methods=['POST'])
def webhook_listener():
    try:
        if not validateRequest(request):
            abort(403)

        data = json.loads(request.data)
        if not 'eventName' in data or not 'data' in data:
            abort(404)

        if data['eventName'] == 'BeforeInstanceLaunch':
            return setHostnameGV(data)

    except Exception as e:
        logging.exception('Exception encountered while processing webhook')
        abort(500)

def setHostnameGV(data):
    client = ScalrApiClient(SCALR_URL, SCALR_API_KEY, SCALR_API_SECRET)
    logging.debug(json.dumps(data, indent=2))
    serverId = data['data']['SCALR_EVENT_SERVER_ID']
    envId = data['data']['SCALR_ENV_ID']
    endpoint = 'api/v1beta0/user/{}/servers/{}/global-variables/{}'.format(envId, serverId, GV_NAME)
    body = {
        'value' : getGVValue(data)
    }
    r = client.patch(endpoint, json=body) # exceptions caught in webhook listener
    logging.debug(r)
    return 'Ok'


def getGVValue(data):
    return binascii.hexlify(hashlib.sha1(data['data']['SCALR_EVENT_SERVER_ID']).digest())[:8]

def validateRequest(request):
    if not 'X-Signature' in request.headers or not 'Date' in request.headers:
        return False
    date = request.headers['Date']
    body = request.data
    expected_signature = binascii.hexlify(hmac.new(SCALR_SIGNING_KEY, body + date, hashlib.sha1).digest())
    if expected_signature != request.headers['X-Signature']:
        return False
    date = dateutil.parser.parse(date)
    now = datetime.now(pytz.utc)
    delta = abs((now - date).total_seconds())
    return delta < 300

class ScalrApiClient(object):
    def __init__(self, api_url, key_id, key_secret):
        self.api_url = api_url
        self.key_id = key_id
        self.key_secret = key_secret
        self.logger = logging.getLogger("api[{0}]".format(self.api_url))
        self.session = ScalrApiSession(self)

    def list(self, path, **kwargs):
        data = []
        ident = False
        while path is not None:
            if ident:
                print
            body = self.session.get(path, **kwargs).json()
            data.extend(body["data"])
            path = body["pagination"]["next"]
            ident = True
        return data

    def create(self, *args, **kwargs):
        self._fuzz_ids(kwargs.get("json", {}))
        return self.session.post(*args, **kwargs).json().get("data")

    def fetch(self, *args, **kwargs):
        return self.session.get(*args, **kwargs).json()["data"]

    def delete(self, *args, **kwargs):
        self.session.delete(*args, **kwargs)

    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs).json()["data"]

    def patch(self, *args, **kwargs):
        return self.session.patch(*args, **kwargs).json()['data']


class ScalrApiSession(requests.Session):
    def __init__(self, client):
        self.client = client
        super(ScalrApiSession, self).__init__()

    def prepare_request(self, request):
        if not request.url.startswith(self.client.api_url):
            request.url = "".join([self.client.api_url, request.url])
        request = super(ScalrApiSession, self).prepare_request(request)

        now = datetime.now(tz=pytz.timezone(os.environ.get("TZ", "UTC")))
        date_header = now.isoformat()

        url = urlparse.urlparse(request.url)

        # TODO - Spec isn't clear on whether the sorting should happen prior or after encoding
        if url.query:
            pairs = urlparse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
            pairs = [map(urllib.quote, pair) for pair in pairs]
            pairs.sort(key=lambda pair: pair[0])
            canon_qs = "&".join("=".join(pair) for pair in pairs)
        else:
            canon_qs = ""

        # Authorize
        sts = "\n".join([
            request.method,
            date_header,
            url.path,
            canon_qs,
            request.body if request.body is not None else ""
        ])

        sig = " ".join([
            "V1-HMAC-SHA256",
            base64.b64encode(hmac.new(str(self.client.key_secret), sts, hashlib.sha256).digest())
        ])

        request.headers.update({
            "X-Scalr-Key-Id": self.client.key_id,
            "X-Scalr-Signature": sig,
            "X-Scalr-Date": date_header,
            "X-Scalr-Debug": "1"
        })

        self.client.logger.debug("URL: %s", request.url)
        self.client.logger.debug("StringToSign: %s", repr(sts))
        self.client.logger.debug("Signature: %s", repr(sig))

        return request

    def request(self, *args, **kwargs):
        res = super(ScalrApiSession, self).request(*args, **kwargs)
        self.client.logger.info("%s - %s", " ".join(args), res.status_code)
        try:
            errors = res.json().get("errors", None)
            if errors is not None:
                for error in errors:
                    self.client.logger.warning("API Error (%s): %s", error["code"], error["message"])
        except ValueError:
            self.client.logger.error("Received non-JSON response from API!")
        res.raise_for_status()
        self.client.logger.debug("Received response: %s", res.text)
        return res

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)
    loadSettings(sys.argv[1] if len(sys.argv) > 1 else '/settings.yaml')
    app.run(debug=True, host='0.0.0.0')
else:
    loadSettings('/settings.yaml')

