from rest_framework_sso.querysets import SessionTokenQuerySet as BaseSessionTokenQuerySet


class SessionTokenQuerySet(BaseSessionTokenQuerySet):
    def for_user(self, user):
        return self.filter(user=user)
