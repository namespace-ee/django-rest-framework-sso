# coding: utf-8
from __future__ import absolute_import, unicode_literals

from django.db.models import QuerySet, Q
from django.utils import timezone

import logging

logger = logging.getLogger(__name__)


class SessionTokenQuerySet(QuerySet):
    def active(self):
        return self.filter(Q(revoked_at__isnull=True) | Q(revoked_at__gt=timezone.now()))

    def with_user_agent(self, request):
        if request.META and "HTTP_USER_AGENT" in request.META:
            return self.filter(user_agent__startswith=request.META.get("HTTP_USER_AGENT")[:100])
        return self
