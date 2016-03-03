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
