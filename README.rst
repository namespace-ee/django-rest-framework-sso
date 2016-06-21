=========================
Django REST Framework SSO
=========================

Django REST Framework SSO is an extension to Django REST Framework that enables
Single sign-on in a microservice-oriented environment using the JWT standard.

Quick start
-----------

1. Add "rest_framework_sso" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'rest_framework_sso',
    ]

2. Include the session and authorization token URLs::

    from rest_framework_sso.views import obtain_session_token, obtain_authorization_token

    urlpatterns = [
        ...
        url(r'^session/', obtain_session_token),
        url(r'^authorize/', obtain_authorization_token),
    ]


Authentication class
--------------------
In order to get-or-create User accounts automatically within your microservice apps,
you can use the following DRF Authentication class template::

    class Authentication(rest_framework_sso.authentication.JWTAuthentication):
        def authenticate_credentials(self, payload):
            user_model = get_user_model()

            user, created = user_model.objects.get_or_create(
                service=payload.get('iss'),
                external_id=payload.get('uid'),
            )

            if not user.is_active:
                raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

            return user, payload
