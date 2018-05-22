from datetime import timedelta, datetime

from django.contrib.auth import login, logout
from rest_framework import status, permissions

from rest_framework.response import Response
from rest_framework.views import APIView

from mt_jwt_auth.jwt_user.authenticators import ObtainJWTCustomAuthentication, JSONWebTokenAuthentication
from mt_jwt_auth.jwt_user.permissions import JWTBasePermission
from mt_jwt_auth.jwt_user.serializers import JSONWebTokenSerializer
from mt_jwt_auth.jwt_user.storages.django_cache import RedisCommonStorage
from mt_jwt_auth.jwt_user.utils.jwt_wraper import JWTAuthDec

JWT_EXPIRATION_DELTA = timedelta(seconds=300000)


def jwt_payload_handler(user):
    username = user.get_username()
    if user.is_anonymous:
        groups = ['anonymous']
        uuid = None
    else:
        groups = list(user.groups.values_list('name', flat=True))
        uuid = str(user.uuid)

    payload = {
        'groups': groups,
        'username': username,
        'uuid': uuid,
        'exp': datetime.utcnow() + JWT_EXPIRATION_DELTA
    }

    return payload


def jwt_token_handler(user, session_key):
    """
    Returns JWT token for Authorization with user information
    Takes user instance and session key as parameters
    """
    # +
    storage = RedisCommonStorage()
    key = str(session_key)
    payload = jwt_payload_handler(user)
    token = JWTAuthDec(keys_storage=storage).create_token(key=key, payload=payload)
    # +
    return token


class BaseJWTAuth(APIView):
    authentication_classes = (ObtainJWTCustomAuthentication,)
    permission_classes = ()
    serializer_class = JSONWebTokenSerializer

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'view': self,
        }

    def get_serializer_class(self):
        """
        Return the class to use for the serializer.
        Defaults to using `self.serializer_class`.
        You may want to override this if you need to provide different
        serializations depending on the incoming request.
        (Eg. admins get full serialization, others get basic serialization)
        """
        assert self.serializer_class is not None, (
            "'%s' should either include a `serializer_class` attribute, "
            "or override the `get_serializer_class()` method."
            % self.__class__.__name__)
        return self.serializer_class

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)


class ObtainJSONWebToken(BaseJWTAuth):
    http_method_names = ['get']

    def get(self, request, *args, **kwargs):
        """
        Returns JWT Authorization token for user that is currently logged in
        """
        user = request.user
        if user.is_authenticated:
            token = jwt_token_handler(user, user.uuid)
        else:
            request.session['jwt_created'] = True
            request.session.save()
            token = jwt_token_handler(user, request.session.session_key)
        return Response(token)


class UserLoginView(BaseJWTAuth):
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):
        """
        Logs in user and returns JWT token with user information
        """
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            # TODO: need check something like is_loggedin
            # if not user.is_authenticated:
            login(request, user)
            token = jwt_token_handler(user, user.uuid)
            return Response(token)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogoutView(BaseJWTAuth):
    http_method_names = ['get']

    def get(self, request, *args, **kwargs):

        if request.user.is_authenticated:
            logout(request)
            request.session['jwt_created'] = True
            request.session.save()
            token = jwt_token_handler(request.user, request.session.session_key)
            return Response(token)

        return Response('Error: Authentication required', status=status.HTTP_401_UNAUTHORIZED)


class TestJWTAuthenticationView(APIView):
    authentication_classes = (JSONWebTokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        return Response({'get', 1})

    def post(self, request, *args, **kwargs):
        return Response({'post', 1})


class TestJWTPermissionView(APIView):
    authentication_classes = ()
    permission_classes = (JWTBasePermission, )

    def get(self, request, *args, **kwargs):
        return Response({'get', 1})

    def post(self, request, *args, **kwargs):
        return Response({'post', 1})
