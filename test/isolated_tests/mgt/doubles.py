from yosai.core import (
    AbstractRememberMeManager,
    SerializationManager,
)


class MockRememberMeManager(AbstractRememberMeManager):

    def __init__(self):
        super().__init__()
        self.serialization_manager = SerializationManager()

    def forget_identity(self):
        pass

    def get_remembered_serialized_identity(self):
        pass

    def remember_serialized_identity(self):
        pass

