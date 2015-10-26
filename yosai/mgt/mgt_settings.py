from yosai import (
    settings,
)


class DefaultMGTSettings:
    """
    DefaultMGTSettings is a settings proxy.  It is new for Yosai.
    It obtains the SecurityManager configuration from Yosai's global settings.
    """
    def __init__(self):

        mgt_config = settings.MGT_CONFIG
        self.default_cipher_key = mgt_config.get('DEFAULT_CIPHER_KEY')
        self.security_manager_config = mgt_config.get('SECURITY_MANAGER')

    def __repr__(self):
        return ("MGTSettings(default_cipher_key={0},"
                "security_manager_config={1})".format(
                self.default_cipher_key, self.security_manager_config))

# initalize module-level settings:
mgt_settings = DefaultMGTSettings()
