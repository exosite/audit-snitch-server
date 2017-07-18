#!/usr/bin/env python3

import os
from base64 import b64encode

print(b64encode(os.urandom(256)).decode("utf-8"))
