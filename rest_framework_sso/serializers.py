# coding: utf-8
from __future__ import absolute_import, unicode_literals

from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from rest_framework_sso.settings import api_settings

import logging

logger = logging.getLogger(__name__)

create_authorization_payload = api_settings.CREATE_AUTHORIZATION_PAYLOAD
encode_jwt_token = api_settings.ENCODE_JWT_TOKEN


class SessionTokenSerializer(serializers.Serializer):
    username = serializers.CharField(label=_("Username"))
    password = serializers.CharField(label=_("Password"), style={"input_type": "password"})
    client_id = serializers.CharField(label=_("Client ID"), allow_blank=True, required=False, default="")

    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")

        if username and password:
            user = authenticate(username=username, password=password)

            if user:
                if not user.is_active:
                    msg = _("User account is disabled.")
                    raise serializers.ValidationError(msg)
            else:
                msg = _("Unable to log in with provided credentials.")
                raise serializers.ValidationError(msg)
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg)

        attrs["user"] = user
        return attrs


class AuthorizationTokenSerializer(serializers.Serializer):
    pass
