from yosai import (
    settings,
)


class AuthenticationSettings(object):
    """
    AuthenticationSettings is a settings proxy.  It is new for Yosai.
    """
    def __init__(self):
        self.authc_config = settings.AUTHC_CONFIG
        self.default_config = self.hashing_service_defaults()

    def __getattr__(self, attr):
        return getattr(self.auch_config, attr, 
                       self.default_config.get(attr, None))

    def hashing_service_defaults(self):
        # hard coded for last-resort configuration
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
