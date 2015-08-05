from yosai import (
    mgt_abcs,
)

class MockRememberMeManager(mgt_abcs.RememberMeManager):

    def get_remembered_identifiers(self, subject_context):
        pass

    def forget_identity(self, subject_context):
        pass

    def on_successful_login(self, subject, authc_token, account):
        pass

    def on_failed_login(self, subject, token, auth_exc):
        pass

    def on_logout(self, subject):
        pass


