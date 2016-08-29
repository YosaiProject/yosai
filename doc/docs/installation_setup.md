# Installation and Setup

## Installation

First, install Yosai from PyPI using pip:
    ``pip install yosai``

Installing from PyPI, using pip, will install the project package that includes
``yosai.core`` and ``yosai.web``, a default configuration, and project dependencies.



## Setup

Yosai is configured through a YAML-formatted settings file.  An example of
this configuration file can be found within the yosai.core.conf  directory
of the Yosai project, named **yosai_settings.yaml**.  When you initialize a Yosai
instance, you specify as an argument *either* a file_path to a configured settings
file or an environment variable that references the location of this file in
the system that will use Yosai:

```python
  #option 1
  yosai = Yosai(env_var='ANY_ENV_VAR_NAME_YOU_WANT')

  #option 2
  yosai = Yosai(file_path='/../../../whatever_filename_you_want.yaml')
```


## Configuration

Following is a copy of the default YAML config file.  As you will see, settings
are organized according to the services that use them:
```
AUTHC_CONFIG:
    default_algorithm: bcrypt_sha256
    hash_algorithms:
        bcrypt_sha256: {}
        sha256_crypt:
            default_rounds: 110000
            max_rounds: 1000000
            min_rounds: 1000
            salt_size: 16

REMEMBER_ME_CONFIG:
    default_cipher_key: you need to update this using the fernet keygen

SECURITY_MANAGER_CONFIG:
    security_manager: yosai.core.NativeSecurityManager
    attributes:
        serializer: cbor
        realms:
            yosai.core.AccountStoreRealm: yosai_alchemystore.AlchemyAccountStore
        cache_handler: yosai_dpcache.cache.DPCacheHandler
        session_attributes_schema: null

SESSION_CONFIG:
    session_timeout:
        absolute_timeout: 1800
        idle_timeout: 300
    session_validation:
        scheduler_enabled: false
        time_interval: 3600

WEB_REGISTRY:
    signed_cookie_secret:  changeme

CACHE_HANDLER:
    init_config:
        backend: 'yosai_dpcache.redis'
        region_name: 'yosai_dpcache'
    server_config:
      redis:
        url: '127.0.0.1'
        host: 'localhost'
        port: 6379
        # password:
        # db:
        # distributed_lock:
        # socket_timeout:
        # lock_timeout:
        # lock_sleep:
        # redis_expiration_time:
        # connection_pool:
    ttl_config:
        absolute_ttl: 3600
        credentials_ttl: 300
        authz_info_ttl: 1800
        session_absolute_ttl: 1800

ALCHEMY_STORE:
    engine_config:
        dialect:
        path:
        userid:
        password:
        hostname:
        port:
        db:
```

### Configuration:  AUTHC_CONFIG

These are cryptographic hashing settings used to configure the ``CryptContext`` object obtained from the ``Passlib`` library.


### Configuration:  MGT_CONFIG

``DEFAULT_CIPHER_KEY`` is a setting that contains a cipher key used by the Fernet key generator.  As you can see, a default value isn't provided and you must generate your own.  This key is used for (de)encryption during "RememberMe" processing. ``yosai.core.mgt.AbstractRememberMeManager``


### Configuration: SESSION_CONFIG

A session has two timeout thresholds: idle and absolute time-to-live.  If you
are using manual session validation, you can manage settings for it within the respective section in the config.  Time is represented in seconds.
