# Installation and Setup

## Installation

First, install Yosai from PyPi:
    ``pip install yosai``

This will install yosai.core, including its default configuration, and
its dependencies.


## Setup

Yosai can be configured in two ways:
- using a YAML config file, whose location must be specified in an environment variable, ``YOSAI_CORE_SETTINGS``
- using Yosai defaults, which are specified in a YAML config file located in the
  /config directory of the yosai package


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


MGT_CONFIG:
    DEFAULT_CIPHER_KEY: you need to update this using the fernet keygen


SESSION_CONFIG:
    session_timeout:
        absolute_timeout: 1800
        idle_timeout: 300
    session_validation:
        scheduler_enabled: false
        time_interval: 3600
```

### Configuration:  AUTHC_CONFIG

These are cryptographic hashing settings used to configure the ``CryptContext`` object obtained from the ``Passlib`` library.


### Configuration:  MGT_CONFIG

``DEFAULT_CIPHER_KEY`` is a setting that contains a cipher key used by the Fernet key generator.  As you can see, a default value isn't provided and you must generate your own.  This key is used for (de)encryption during "RememberMe" processing. ``yosai.core.mgt.AbstractRememberMeManager``


### Configuration: SESSION_CONFIG

A session has two timeout thresholds: idle and absolute time-to-live.  If you
are using manual session validation, you can manage settings for it within the respective section in the config.  Time is represented in seconds.
