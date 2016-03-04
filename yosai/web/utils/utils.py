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


class SessionDescriptor(web_abcs.WebDescriptor):

    def __get__(self, instance, cls):
        print('getting scd')

    def __set__(self, instance, value):
        print('setting scd')

    def __delete__(self, instance):
        pass


class SessionCreationDescriptor(web_abcs.WebDescriptor):

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
    """

    remember_me = RememberMeDescriptor()
    remote_host = HostDescriptor()
    session = SessionDescriptor()
    session_creation_enabled = SessionCreationDescriptor()

    def __init__(self, session=None, remember_me=None, remote_host=None,
                 session_creation_enabled=True):
        self.session = session
        self.remember_me = remember_me
        self.remote_host = remote_host
        self.session_creation_enabled = session_creation_enabled

    def ensure_padding(self, base64):
        """
        Sometimes a user agent will send the rememberMe cookie value without
        padding, most likely because `=` is a separator in the cookie header.

        :param base64: the base64 encoded String that may need to be padded
        :returns: the base64 String, padded if necessary
        """

        pad = b'=' * (((~len(base64)) + 1) & 3)
        base64 = base64 + pad
        return base64

    # not sure about this process, yet -- TBD (moved from WebSecurityManager):
    def remove_identity(self):
        """
        removes user identity from the request object
        """
        pass
