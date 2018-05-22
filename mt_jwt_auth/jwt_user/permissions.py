from rest_framework import permissions

from mt_jwt_auth.jwt_user.jwt_user import JWTUser
from mt_jwt_auth.jwt_user.utils.common import jwt_decode_handler, get_jwt_value


class JWTBasePermission(permissions.BasePermission):

    def has_permission(self, request, view):
        """
        Returns True if user is authenticated and ads JWT_user instance
        with user information to request
        """
        token = get_jwt_value(request)
        if token is None:
            return False
        else:
            # TODO: check payload ? how ?
            payload = jwt_decode_handler(token)
            request.jwt_user = JWTUser(payload)
            return True

    def has_object_permission(self, request, view, obj):
        """
        Returns True if user is allowed to act on particular object
        """
        return True


class AnyGroupJWTBasePermission(JWTBasePermission):

    '''
        give access for all authenticated users that belong to any group
    '''

    def has_permission(self, request, view):
        # TODO Temp. Remove as deprecated when all mt_jwt_auth use jwt authentication
        old_perm = False

        try:
            # For old jwt token parsing logic
            old_perm = (super().has_permission(request, view) and
                        request.jwt_payload.get('uuid') and
                        request.jwt_payload.get('groups'))
        except:
            # Just go to check the new permission
            pass

        return old_perm or (request.user.is_authenticated and request.groups)
