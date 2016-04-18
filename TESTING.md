To run the tests you need to install additional requirements:
```bash
pip install pytest
pip install pytest-catchlog
```

Tests are categorized as integrated and isolated (unit).  

Integrated tests are used for complete, end-to-end tests.  Consequently, integrated tests require a cache and accountstore.  For integrated testing, YosaiAlchemyStore is used with a sqlite backend and YosaiDPCache with a redis backend.  

Isolated (unit) tests are independent tests which use a mix of classic and mock testing.  Neither extension project is needed to run them.

See the README.md for each extension project (YosaiAlchemyStore and YosaiDPCache) as it explains how to configure the project.  Both projects follow a similar convention.

To run integrated tests, use the env-config-file approach, defining system environment variables that reference the locations of the yaml files required for yosai, yosai_alchemystore, and yosai_dpcache and ensure that file readable permissions:

YOSAI_CORE_SETTINGS=/path/to/your/yosai_settings.yaml
YOSAI_CACHE_SETTINGS=/path/to/your/cache_settings.yaml
YOSAI_ALCHEMYSTORE_SETTINGS=/path/to/your/accountstore_settings.yaml

Again, Yosai uses sqlite as the backend for AlchemyAccountStore for integrated testing.  The accountstore_settings.yaml is simply:

    ENGINE_CONFIG: 
        dialect:  sqlite
        path: '//'
        userid:
        password:
        hostname:
        port:
        db:

