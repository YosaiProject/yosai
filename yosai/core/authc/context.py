"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

from yosai.core import (
    AuthenticationSettingsContextException,
    CryptContextException,
    MissingHashAlgorithmException,
    MissingPrivateSaltException,
    settings,
)

from passlib.context import CryptContext


class AuthenticationSettings():
    """
    AuthenticationSettings is a settings proxy.  It is new for Yosai.
    It obtains the authc configuration from Yosai's global settings.
    """
    def __init__(self):
        self.authc_config = settings.AUTHC_CONFIG
        self.default_algorithm = self.authc_config.get('default_algorithm', 
                                                       'bcrypt_sha256')
        self.algorithms = self.authc_config.get('hash_algorithms', None)
        # no default private salt because it is too risky (lazy developers)
        self.private_salt = self.authc_config.get('private_salt', None)
        # private salt is a best practice, so enforce it as a policy:
        if not self.private_salt:
            raise MissingPrivateSaltException

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


class CryptContextFactory():
    """
    New to Yosai.  CryptContextFactory proxies passlib's CryptContext api.
    """

    def __init__(self, authc_settings):
        """
        :type authc_settings: AuthenticationSettings
        """
        self.authc_settings = authc_settings 

    def generate_context(self, algorithm):

        authc_config = self.authc_settings.get_config(algorithm) 
                         
        """
        This method is new to Yosai and not a port from Shiro.  It is
        the primary configurable api for passlib hash management.

        :param algorithm:  the algorithm name as recognized by passlib
        :param authc_config: the dict of a specific algorithm's settings
        :returns: a passlib CryptContext object
        """
        if (not algorithm): 
            msg = "hashing algorithm missing"
            raise MissingHashAlgorithmException(msg)

        context = dict(schemes=[algorithm])
        
        context.update({"{0}__{1}".format(algorithm, key): value 
                       for key, value in authc_config.items()}) 
        return context

    def create_crypt_context(self, 
                             algorithm=None):
        """
        :type request: HashRequest
        :returns: CryptContext
        """
        if not algorithm:
            algorithm = self.authc_settings.default_algorithm 

        context = self.generate_context(algorithm) 

        try:
            myctx = CryptContext(**context)

        except (AttributeError, TypeError, KeyError):
            raise CryptContextException

        return myctx
    
    def __repr__(self):
        return ("<CryptContextFactory(authc_settings={0})>".
                format(self.authc_settings))


# module-level settings, defined at initialization:
authc_settings = AuthenticationSettings()
