from yosai import (
    AbstractRememberMeManager,
)


class MockRememberMeManager(AbstractRememberMeManager):

    def get_remembered_identifiers(self, subject_context):
        pass

    def forget_identity(self, subject_context):
        pass

    def on_failed_login(self, subject, token, auth_exc):
        pass

    def on_logout(self, subject):
        pass

    def remember_serialized_identity(subject, serialized):
        pass

    def get_remembered_serialized_identity(subject_context):
        pass


