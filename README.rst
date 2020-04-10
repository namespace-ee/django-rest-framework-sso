=========================
Django REST Framework SSO
=========================

Django REST Framework SSO is an extension to Django REST Framework that enables
Single sign-on in a microservice-oriented environment using the JWT standard.

This library provides two types of JWT tokens:

1. non-expiring session tokens for your primary login application (aka. "refresh tokens")

2. short-lived authorization tokens for accessing your other apps (these contain permissions given by the primary app)

The client is expected to first login to your primary login application by POSTing an username and password. The client will receive a permanent session token that will allow subsequent requests to the same server be authenticated. These tokens do not contain any permissions/authorization information and cannot be used for SSO into other apps.

Afterwards, the client is expected to obtain and keep updating authorization tokens using the session token. These secondary tokens are short-lived (15mins..1 hour) and contain the permissions that the user has at the time of issuance. These tokens are used to access other services, which then trust the permissions in the JWT payload for the lifetime of the token.

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

Additional data in authorization tokens
---------------------------------------
For example, you may want to include an `account` field in your JWT authorization tokens,
so that `otherapp` will know about the user's permissions. To do this, you may need to override
the ObtainAuthorizationTokenView and AuthorizationTokenSerializer::

    class ObtainAuthorizationTokenView(rest_framework_sso.views.ObtainAuthorizationTokenView):
        """
        Returns a JSON Web Token that can be used for authenticated requests.
        """
        serializer_class = AuthorizationTokenSerializer


    class AuthorizationTokenSerializer(serializers.Serializer):
        account = serializers.HyperlinkedRelatedField(
            queryset=Account.objects.all(),
            required=True,
            view_name='api:account-detail',
        )

        class Meta:
            fields = ['account']

Replace the authorization token view in your URL conf::

    urlpatterns = [
        url(r'^authorize/$', ObtainAuthorizationTokenView.as_view()),
        ...
    ]

Add the `account` keyword argument to the `create_authorization_payload` function::

    from rest_framework_sso import claims

    def create_authorization_payload(session_token, user, account, **kwargs):
        return {
            claims.TOKEN: claims.TOKEN_AUTHORIZATION,
            claims.SESSION_ID: session_token.pk,
            claims.USER_ID: user.pk,
            claims.EMAIL: user.email,
            'account': account.pk,
        }

You will need to activete this function in the settings::

    REST_FRAMEWORK_SSO = {
        'CREATE_AUTHORIZATION_PAYLOAD': 'myapp.authentication.create_authorization_payload',
        ...
    }

JWT Authentication
------------------
In order to get-or-create User accounts automatically within your microservice apps,
you may need to write your custom JWT payload authentication function::

    from django.contrib.auth import get_user_model
    from rest_framework_sso import claims
    
    def authenticate_payload(payload):
        user_model = get_user_model()
        user, created = user_model.objects.get_or_create(
            service=payload.get(claims.ISSUER),
            external_id=payload.get(claims.USER_ID),
        )
        if not user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))
        return user


Enable authenticate_payload function in REST_FRAMEWORK_SSO settings::

    REST_FRAMEWORK_SSO = {
        'AUTHENTICATE_PAYLOAD': 'otherapp.authentication.authenticate_payload',
        ...
    }

Enable JWT authentication in the REST_FRAMEWORK settings::

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'rest_framework_sso.authentication.JWTAuthentication',
            'rest_framework.authentication.SessionAuthentication',
            ...
        ),
        ...
    }

Requests that have been successfully authenticated with JWTAuthentication contain
the JWT payload data in the `request.auth` variable. This data can be used in your
API views/viewsets to handle permissions, for example::

    from rest_framework_sso import claims
    
    class UserViewSet(viewsets.ReadOnlyModelViewSet):
        serializer_class = UserSerializer
        queryset = User.objects.none()

        def get_queryset(self):
            if not request.user.is_authenticated or not request.auth:
                return self.none()
            return User.objects.filter(
                service=request.auth.get(claims.ISSUER),
                external_id=request.auth.get(claims.USER_ID),
            )

Settings
--------
Example settings for project that both issues and validates tokens for `myapp` and `otherapp`::

    REST_FRAMEWORK_SSO = {
        'CREATE_AUTHORIZATION_PAYLOAD': 'myapp.authentication.create_authorization_payload',
        'IDENTITY': 'myapp',
        'SESSION_AUDIENCE': ['myapp'],
        'AUTHORIZATION_AUDIENCE': ['myapp', 'otherapp'],
        'ACCEPTED_ISSUERS': ['myapp'],
        'KEY_STORE_ROOT': '/srv/myapp/keys',
        'PUBLIC_KEYS': {
            'myapp': ['myapp-20200410.pem', 'myapp-20180101.pem'],  # both private/public key in the same file
        },
        'PRIVATE_KEYS': {
            'myapp': ['myapp-20200410.pem', 'myapp-20180101.pem'],  # both private/public key in the same file
        },
    }
    
Example settings for project that only accepts tokens signed by `myapp` public key for `otherapp`::

    REST_FRAMEWORK_SSO = {
        'AUTHENTICATE_PAYLOAD': 'otherapp.authentication.authenticate_payload',
        'VERIFY_SESSION_TOKEN': False,
        'IDENTITY': 'otherapp',
        'ACCEPTED_ISSUERS': ['myapp'],
        'KEY_STORE_ROOT': '/srv/otherapp/keys',
        'PUBLIC_KEYS': {
            'myapp': ['myapp-20200410.pem', 'myapp-20180101.pem'],  # only public keys in these files
        },
    }

Full list of settings parameters with their defaults::

    REST_FRAMEWORK_SSO = {
        'CREATE_SESSION_PAYLOAD': 'rest_framework_sso.utils.create_session_payload',
        'CREATE_AUTHORIZATION_PAYLOAD': 'rest_framework_sso.utils.create_authorization_payload',
        'ENCODE_JWT_TOKEN': 'rest_framework_sso.utils.encode_jwt_token',
        'DECODE_JWT_TOKEN': 'rest_framework_sso.utils.decode_jwt_token',
        'AUTHENTICATE_PAYLOAD': 'rest_framework_sso.utils.authenticate_payload',

        'ENCODE_ALGORITHM': 'RS256',
        'DECODE_ALGORITHMS': None,
        'VERIFY_SIGNATURE': True,
        'VERIFY_EXPIRATION': True,
        'VERIFY_ISSUER': True,
        'VERIFY_AUDIENCE': True,
        'VERIFY_SESSION_TOKEN': True,
        'EXPIRATION_LEEWAY': 0,
        'SESSION_EXPIRATION': None,
        'AUTHORIZATION_EXPIRATION': datetime.timedelta(seconds=300),

        'IDENTITY': None,
        'SESSION_AUDIENCE': None,
        'AUTHORIZATION_AUDIENCE': None,
        'ACCEPTED_ISSUERS': None,
        'KEY_STORE_ROOT': None,
        'PUBLIC_KEYS': {},
        'PRIVATE_KEYS': {},

        'AUTHENTICATE_HEADER': 'JWT',
    }

Generating RSA keys
-------------------
You can use openssl to generate your public/private key pairs::

    $ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    $ openssl rsa -pubout -in private_key.pem -out public_key.pem
    $ cat private_key.pem public_key.pem > keys/myapp-20180101.pem

