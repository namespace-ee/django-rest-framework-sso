import logging
import uuid

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

from rest_framework_sso.querysets import SessionTokenQuerySet

logger = logging.getLogger(__name__)


class SessionToken(models.Model):
    """
    The default session token model.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, db_index=True)
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, related_name="+", on_delete=models.CASCADE, verbose_name=_("user")
    )
    client_id = models.CharField(max_length=1000, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.CharField(max_length=1000, blank=True)
    version = models.CharField(max_length=100, blank=True, null=True)
    last_used_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_issued_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        related_name="+",
        on_delete=models.CASCADE,
        verbose_name=_("created by"),
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = SessionTokenQuerySet.as_manager()

    class Meta:
        abstract = "rest_framework_sso" not in settings.INSTALLED_APPS
        verbose_name = _("Session token")
        verbose_name_plural = _("Session tokens")

    def __str__(self):
        return str(self.id)

    def update_attributes(self, request):
        if request.META.get("HTTP_X_FORWARDED_FOR"):
            self.ip_address = request.META.get("HTTP_X_FORWARDED_FOR").split(",")[0].strip()
        elif request.META.get("REMOTE_ADDR"):
            self.ip_address = request.META.get("REMOTE_ADDR").split(",")[0].strip()
        else:
            self.ip_address = None

        if request.META.get("HTTP_USER_AGENT"):
            self.user_agent = request.META.get("HTTP_USER_AGENT")[:1000]
        else:
            self.user_agent = ""

        self.version = getattr(request, "version", None)
