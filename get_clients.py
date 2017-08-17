#!/usr/bin/env python3

import os
import sys
import hmac

from datetime import datetime, timezone
from base64 import b64encode, b64decode

import requests
import requests.packages.urllib3

from requests.packages.urllib3.exceptions import SubjectAltNameWarning

b64_hmac_key = os.getenv("SNITCH_API_KEY")
hmac_key = b64decode(b64_hmac_key, validate=True)

now = int(datetime.now(timezone.utc).timestamp())
timestamp_str = str(now)

hm = hmac.new(hmac_key, msg=timestamp_str.encode(), digestmod='SHA256')

headers = {
    'Request-Timestamp': timestamp_str,
    'Timestamp-Signature': b64encode(hm.digest()),
}

snitch_server = os.getenv("SNITCH_SERVER")
url = "https://{}/v1/clients".format(snitch_server)

requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
r = requests.get(url, headers=headers, verify=os.getenv("SNITCH_CA_PATH"))
if r.status_code == 200:
    for client, ports in r.json().items():
        if len(ports) > 1:
            print("{}: More than one connection!".format(client))
        else:
            print(client)
    sys.exit(0)
else:
    print(r.text)
    sys.exit(1)
