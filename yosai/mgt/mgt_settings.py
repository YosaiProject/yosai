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

    def __repr__(self):
        return ("MGTSettings({0})".format(self.default_cipher_key))

# initalize module-level settings:
mgt_settings = DefaultMGTSettings()
