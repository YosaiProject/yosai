from yosai import (
    settings,
)


class AuthenticationSettings(object):
    """
    AuthenticationSettings is a settings proxy.  It is new for Yosai.
    """
    def __init__(self):
        self.authc_config = settings.AUTHC_CONFIG
        self.default_algo = self.authc_config.get('default_algorithm', None)
        self.default_config = self.get_hashing_defaults()

    def __getattr__(self, attr):
        return self.default_config.get(attr, None)

    def get_hashing_defaults(self):
        if self.default_algo:
            hashalgos = self.authc_config.get('hash_algorithms', None)
            if hashalgos:
                default_config = hashalgos.get(self.default_algo, None)
        if default_config is not None:
            return default_config
        else:
            # hard coded for last-resort configuration:
            return {
                "default_algorithm": "bcrypt_sha256",
                "hash_algorithms": {
                    "bcrypt_sha256": {
                        "default_rounds": 200000,
                    },
                    "sha256_crypt": {
                        "default_rounds": 110000,
                        "max_rounds": 1000000,
                        "min_rounds": 1000,
                        "salt_size": 16}},
                "private_salt": "privatesalt"
            }
