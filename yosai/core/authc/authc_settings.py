
class AuthenticationSettings:
    """
    AuthenticationSettings is a settings proxy.  It is new for Yosai.
    It obtains the authc configuration from Yosai's global settings.
    """
    def __init__(self, settings):
        self.authc_config = settings.AUTHC_CONFIG
        self.default_algorithm = self.authc_config.get('default_algorithm',
                                                       'bcrypt_sha256')
        self.algorithms = self.authc_config.get('hash_algorithms', None)
        self.account_lock_threshold = self.authc_config.get('account_lock_threshold',
                                                            None)

    def get_config(self, algo):
        """
        obtains a dict of the underlying authc_config for an algorithm
        """
        if self.algorithms:
            return self.algorithms.get(algo, {})
        return {}

    def __repr__(self):
        return ("AuthenticationSettings(default_algorithm={0}, algorithms={1},"
                "authc_config={2}".format(self.default_algorithm,
                                          self.algorithms, self.authc_config))
