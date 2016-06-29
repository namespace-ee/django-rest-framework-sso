# coding: utf-8
from __future__ import absolute_import, unicode_literals

import os

DEBUG_PROPAGATE_EXCEPTIONS = True
SECRET_KEY = 'drf-sso'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}
REST_FRAMEWORK_SSO = {
    'KEY_STORE_ROOT': os.path.join(os.path.dirname(__file__), 'keys'),
    'PRIVATE_KEYS': {'test-issuer': ['test-2048.pem', 'test-1024.pem']},
    'PUBLIC_KEYS': {'test-issuer': ['test-2048.pem', 'test-1024.pem']},
}
