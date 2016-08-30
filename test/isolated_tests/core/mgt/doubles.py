from yosai.core import (
    AbstractRememberMeManager,
    SerializationManager,
)


class MockRememberMeManager(AbstractRememberMeManager):

    def __init__(self, settings, session_attributes):
        super().__init__(settings)
        self.serialization_manager = SerializationManager(session_attributes)

    def forget_identity(self):
        pass

    def get_remembered_encrypted_identity(self):
        pass

    def remember_encrypted_identity(self, subject, serialized):
        pass

