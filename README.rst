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

2. Include the session and authorization token URLs:

    from rest_framework_sso.views import obtain_session_token, obtain_authorization_token

    urlpatterns = [
        ...
        url(r'^session/', obtain_session_token),
        url(r'^authorize/', obtain_authorization_token),
    ]
