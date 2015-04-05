import copy
from passlib.context import CryptContext
from yosai import (
    CryptContextException,
    InvalidArgumentException,
    MissingPrivateSaltException,
    MissingDefaultHashAlgorithm,
    PepperPasswordException,
    settings,
)

AUTHC_CONFIG = settings.AUTHC_CONFIG


class DefaultHashService(object):

    def __init__(self): 
        self.default_context = self.generate_default_context()
        self.private_salt = AUTHC_CONFIG.get('private_salt', None)  # pepper
        if self.private_salt is None:
            raise MissingPrivateSaltException('must configure a private salt')

    @property
    def private_salt(self):
        return self._private_salt

    @private_salt.setter
    def private_salt(self, salt):
        print('salt: ', salt)
        if (salt):
            try:
                self._private_salt = bytearray(salt, 'utf-8')
            except (TypeError, AttributeError):
                raise InvalidArgumentException('private salt must be string: ',
                                               salt)
        else:
            raise InvalidArgumentException('no salt argument passed')

    def compute_hash(self, request):
        """
        :returns: dict
        """
        if (not request or not request.source):
            return None 
        
        crypt_context = self.generate_crypt_context(request)

        """
          A few differences between Shiro and Yosai regarding salts:
          1) Shiro generates its own public salt whereas Yosai defers salt
             creation to passlib
          2) Shiro concatenates the PUBLIC SALT with its PRIVATE SALT (pepper).
             Unlike Shiro, Yosai concaentates the PRIVATE SALT with the 
             PASSWORD (rather than a public salt).  The peppered password
             is salted by passlib according to the cryptcontext settings
             else default passlib settings.
        """
        try:
            peppered_pass = self.private_salt + request.source  # s/b bytearray 
        except (AttributeError, TypeError):
            msg = "could not pepper password"
            raise PepperPasswordException(msg)
       
        # Shiro's SimpleHash functionality is replaced by that of passlib's
        # CryptoContext API.  With that given, rather than return a SimpleHash
        # object from this compute method, Yosai now simply returns a dict
        result = {}
        result['ciphertext'] = bytearray(crypt_context.encrypt(peppered_pass))
        result['config'] = crypt_context.to_dict() 

        return result  # DG:  this design is unique to Yosai, not Shiro 

    def generate_default_context(self):
        """
        This method is new to Yosai and not a port from Shiro.  It is part
        of the adaptation to using passlib for hash management.

        :type context: dict
        :param context: The context parameter is a dict in the format that is 
                       recognized by passlib to generate a CryptContext obj.  
                        The context parameter contains the hashing schemes 
                        supported by passlib.  Each hashing scheme, if enabled
                        by passlib, may have custom settings defined for it in 
                        a dict.

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
        hash_settings = AUTHC_CONFIG.get('hash_algorithms', None)
        context = dict(schemes=list(hash_settings.keys()))
        if (not context):
            msg = "must specify a default hash algorithm"
            raise MissingDefaultHashAlgorithm(msg)

        for key, value in hash_settings.items(): 
            context.update({"{0}__{1}".format(key, k): v for k, v in 
                           value.items() if isinstance(value, dict)})
        return context

    def generate_crypt_context(self, request): 
        """
        :type request: HashRequest
        :returns: CryptContext
        """
        context = {}
        algo = self.get_algorithm_name(request)
        context['scheme'] = algo
        iterations = self.get_iterations(request)
        if (iterations):
            context[algo + "__default_rounds"] = iterations

        try:
            myctx = CryptContext(**context)

        except (AttributeError, TypeError, KeyError):
            raise CryptContextException

        return myctx

    def get_algorithm_name(self, request):
        """
        :type request: HashRequest
        """
        name = request.algorithm_name
        if (name is None):
            name = self.default_context.get('schemes', None)[0]  # default val
        
        return name

    def get_iterations(self, request):
        """
        :type request: HashRequest
        """
        iterations = request.iterations
        if (iterations is None):
            default_algorithm = self.get_algorithm_name(request)
            iterations = self.default_context.get(default_algorithm +
                                                  '__default_rounds', None)
        
        # if iterations is none, defer to passlib default
        return iterations

    # DG: removed combine method


class HashRequest(object):
    """ This is an interface in Shiro but I've changed it to a concrete class
        for Yosai, eliminating the builder pattern using idiomatic python
        keyword arg initialization

        I am omitting salt, deferring salt generation to passlib
    """

    def __init__(self, 
                 source=None,
                 iterations=0,
                 algorithm_name=None):

        self.source = source
        self.iterations = iterations
        self.algorithm_name = algorithm_name

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, source=None):
        if source is not None:
            if isinstance(source, str):
                self._source = bytearray(source, 'utf-8')
            elif isinstance(source, bytearray):
                self._source = source
            else:
                msg = 'HashRequest expects str or bytearray'
                raise InvalidArgumentException(msg)

