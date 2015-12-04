from yosai.core import (
    AbstractRememberMeManager,
)


class MockRememberMeManager(AbstractRememberMeManager):

    def forget_identity(self, subject_context):
        pass

    def remember_serialized_identity(subject, serialized):
        pass

    def get_remembered_serialized_identity(subject_context):
        pass


