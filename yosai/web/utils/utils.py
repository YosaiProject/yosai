from yosai.web import (
    web_abcs,
)


class HostDescriptor(web_abcs.WebDescriptor):

    def __get__(self, instance, cls):
        print('getting host')

    def __set__(self, instance, value):
        print('setting host')

    def __delete__(self, instance):
        pass


class SessionIDDescriptor(web_abcs.WebDescriptor):

    def __get__(self, instance, cls):
        print('getting scd')

    def __set__(self, instance, value):
        print('setting scd')

    def __delete__(self, instance):
        pass


class SessionCreationEnabledDescriptor(web_abcs.WebDescriptor):

    def __get__(self, instance, cls):
        print('getting scd')

    def __set__(self, instance, value):
        print('setting scd')

    def __delete__(self, instance):
        pass


class RememberMeDescriptor(web_abcs.WebDescriptor):

    def __get__(self, instance, cls):
        print('getting rmcd')

    def __set__(self, instance, value):
        print('setting rmcd')

    def __delete__(self, instance):
        pass


class WebRegistry:
    """
    Cookie attributes (path, domain, maxAge, etc) may be set on this class's
    default ``cookie`` attribute, which acts as a template to use to set all
    properties of outgoing cookies created by this implementation.

    The default cookie has the following attribute values set:

    |Attribute Name|    Value
    |--------------|----------------
    | name         | rememberMe
    | path         | /
    | max_age      | Cookie.ONE_YEAR

    http-only attribute support

    shiro marked cookies as deleted and ignored those because cookies weren't
    immediately removed by browsers (or through servlets?).. not sure how to
    address this in Yosai yet (TBD)

    removed cookies should return None values for their __get__'s

    set http-only to True

    Note:  when session is created, REFERENCED_SESSION_ID_SOURCE attribute is
    removed from the servlet and REFERENCED_SESSION_IS_NEW attribute gets set

    removing a cookie entails removing from request and response objects

    take a close look at the cookie arguments used in the SessionManager,
    including:
        REFERENCED_SESSION_ID
        REFERENCED_SESSION_ID_SOURCE
        REFERENCED_SESSION_IS_NEW
        REFERENCED_SESSION_ID_IS_VALID
    """

    remember_me = RememberMeDescriptor()
    remote_host = HostDescriptor()
    session_id = SessionIDDescriptor()
    session_creation_enabled = SessionCreationEnabledDescriptor()

    def __init__(self, session_id=None, remember_me=None, remote_host=None,
                 session_creation_enabled=True):
        self.session_id = session_id
        self.remember_me = remember_me
        self.remote_host = remote_host
        self.session_creation_enabled = session_creation_enabled

    # not sure about this process, yet -- TBD (moved from WebSecurityManager):
    def remove_identity(self):
        """
        removes user identity from the request object
        """
        pass

    @property
    def is_web(self):
        pass

    def get_uri_path_segment_param_value(self, request, param_name):
        """
        :type request: WSGIRequest
        :type param_name: String
        """

        if not isinstance(wsgi_request, HttpWSGIRequest):
            return None

        uri = request.request_uri

        if uri is None:
            return None

        try:
            # try to get rid of the query string
            uri = uri[:uri.index('?')]
        except ValueError:
            pass

        try:
            index = uri.index(';')
        except ValueError:
            # no path segment params - return
            return None

        # there are path segment params, so let's get the last one that
        # may exist:

        # uri now contains only the path segment params
        uri = uri[(index + 1):]

        token = param_name + "="
        # we only care about the last param (SESSIONID):
        index = uri.rfind(token)
        if (index < 0):
            # no segment param:
            return None

        uri = uri[index + len(token):]

        try:
            # strip off any remaining segment params:
            index = uri.index(';')
            uri = uri[0:index]
        except:
            pass

        # what remains is the value:
        return uri
