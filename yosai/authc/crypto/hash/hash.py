import copy
from passlib.context import CryptContext
from yosai import (
    InvalidHashAlgorithmException,
    settings,
)

AUTHC_CONFIG = settings.AUTHC_CONFIG


def generate_cryptcontext(context=None):
    """
    :type context: dict
    :param context: The context parameter is a dict in the format that is 
                    recognized by passlib to generate a CryptContext object.  
                    The context parameter contains the hashing schemes 
                    supported by passlib.  Each hashing scheme, if enabled
                    by passlib, may have custom settings defined for it in a 
                    dict.

    :rtype: CryptContext
    :returns: a passlib CryptContext object

     
        "AUTHC_CONFIG": {
                "hash_algorithms": {
                    "bcrypt_sha256": {}   # must be an empty dict
                    "sha256_crypt": {
                            "default_rounds": 110000,
                            "max_rounds": 1000000,
                            "min_rounds": 1000,
                            "salt_size": 16
                    }
                }
                "private_salt": "..."
        }
    """
    # If algorithms aren't passed as parameters, revert to global settings
    if (not context):
        hash_settings = AUTHC_CONFIG.get('hash_algorithms', None)
        context = dict(schemes=list(hash_settings.keys()))
        for key, value in hash_settings.items(): 
            context.update({"{0}__{1}".format(key, k): v for k, v in 
                           value.items() if isinstance(value, dict)})
    try:
        myctx = CryptContext(**context)

    except (AttributeError, TypeError, KeyError):
        raise InvalidHashAlgorithmException

    return myctx


class DefaultHashService(object):

    def __init__(self): 
        self.algorithm_name = "SHA-512"
        self.iterations = 1
        self.generate_public_salt = False
        self.rng = SecureRandomNumberGenerator()
        self.private_salt = None

    def compute_hash(self, request):
        if (not request or not request.source):
            return None 

        algorithm_name = self.get_algorithm_name(request)
        source = request.source
        iterations = self.get_iterations(request)

        public_salt = self.get_public_salt(request)
        salt = self.combine(self.private_salt, public_salt)

        computed = SimpleHash(algorithm_name, source, salt, iterations)

        result = SimpleHash(algorithm_name)
        result.bytes = computed.bytes
        result.iterations = iterations
        #  Only expose the public salt - not the real/combined salt that 
        #  might have been used:
        result.salt = public_salt

        return result

    def get_algorithm_name(self, request):
        name = request.algorithm_name
        if (name is None):
            name = self.algorithm_name
        
        return name

    def get_iterations(self, request):
        iterations = max(0, request.iterations)
        if (iterations < 1):
            iterations = max(1, self.iterations)
        
        return iterations

    def get_public_salt(self, request):

        public_salt = copy.copy(request.salt)

        if (public_salt):
            # a public salt was explicitly requested to be used, so do so:
            return public_salt
        
        public_salt = None

        # check to see if we need to generate one:
        private_salt = copy.copy(self.private_salt)

        """
        If a private salt exists, we must generate a public salt to protect the
        integrity of the private salt.  Or generate it if the instance is
        explicitly configured to do so:
        """
        if (private_salt or self.generate_public_salt):
            public_salt = self.rng.next_bytes()

        return public_salt
    
    def combine(self, private_salt=None, public_salt=None):
        private_salt_bytes = getattr(private_salt, 'bytes', None)
        public_salt_bytes = getattr(public_salt, 'bytes', None)

        if (not private_salt_bytes and not public_salt_bytes):
            return None 
        
        return ((private_salt_bytes if private_salt_bytes else bytearray()) 
                + (public_salt_bytes if public_salt_bytes else bytearray()))
