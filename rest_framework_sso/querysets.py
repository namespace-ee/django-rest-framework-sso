# coding: utf-8
from __future__ import absolute_import, unicode_literals

from django.db.models import QuerySet, Q
from django.utils import timezone

import logging

logger = logging.getLogger(__name__)


class SessionTokenQuerySet(QuerySet):
    def active(self):
        return self.filter(Q(revoked_at__isnull=True) | Q(revoked_at__gt=timezone.now()))

    def first_or_create(self, request_meta=None, **kwargs):
        """
        Looks up an object with the given kwargs, creating one if necessary.
        Returns a tuple of (object, created), where created is a boolean
        specifying whether an object was created.
        """
        if request_meta and "HTTP_USER_AGENT" in request_meta:
            kwargs["user_agent__startswith"] = request_meta.get("HTTP_USER_AGENT")[:100]

        obj = self.filter(**kwargs).first()
        created = False
        if not obj:
            obj = self.create(**kwargs)
            created = True

        return obj, created
