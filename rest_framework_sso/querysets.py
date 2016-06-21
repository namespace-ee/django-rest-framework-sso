# coding: utf-8
from __future__ import absolute_import, unicode_literals

from django.db.models import QuerySet, Q
from django.utils import timezone


class SessionTokenQuerySet(QuerySet):
    def active(self):
        return self.filter(Q(revoked_at__isnull=True) | Q(revoked_at__gt=timezone.now()))

    def first_or_create(self, defaults=None, request_meta=None, **kwargs):
        """
        Looks up an object with the given kwargs, creating one if necessary.
        Returns a tuple of (object, created), where created is a boolean
        specifying whether an object was created.
        """
        if request_meta and 'HTTP_USER_AGENT' in request_meta:
            kwargs['user_agent__startswith'] = request_meta.get('HTTP_USER_AGENT')[:100]

        lookup, params = self._extract_model_params(defaults, **kwargs)
        # The get() needs to be targeted at the write database in order
        # to avoid potential transaction consistency problems.
        self._for_write = True

        obj = self.filter(**lookup).first()
        if obj:
            return obj, False
        else:
            return self._create_object_from_params(lookup, params)
