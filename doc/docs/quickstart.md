# Yosai:  Quick-Start

Yosai is a powerful framework that can take you far.  This Quick-Start
guide is intended to help you get started by going through basic usage while
not burdening you with detail.  This is an opinionated quick-start in that it
requires that you use Redis for caching and a relational database for your
data store.


## Overview

Following are the steps that you will go through to use Yosai:

1. Install
2. Configure
3. Extend
4. Instantiate
5. Use


## Install

First, install Yosai from PyPI using pip:
```bash
pip install yosai
```

Installing from PyPI, using pip, will install the project package that includes
``yosai.core`` and ``yosai.web``, a default configuration, and project dependencies.


## Configure

Yosai can be configured in a couple of ways, but since you are quick-starting
you will use Yosai's default settings.  You don't have to do any extra work
to make use of the default settings.


## Extend

### Caching

Yosai has full support for caching, including serialization.  Take advantage
of this and use it.

To get you started, there's an extension library, ``yosai_dpcache``, that is a
fork of Mike Bayer's popular "dogpile" projects -- core and cache -- this is
customized for Yosai's serialization preferences.  Currently, ``yosai_dpcache``
supports Redis but a PR for Memcached, Riak, or other cache stores is welcome.

Install yosai_dpcache from PyPI using pip:
```bash
pip install yosai_dpcache
```

``yosai_dpcache`` is configured either through a settings file + env variable or
by instantiating a DPCacheHandler object with settings arguments. For quickstart
purposes, pass the Redis server settings as arguments:

```python
from yosai_dpcache.cache import DPCacheHandler


# time values are denominated in seconds:
ttl = {
    'absolute_ttl': 3600,
    'credentials_ttl': 300,
    'authz_info_ttl': 1800,
    'session_absolute_ttl': 1800
}

# this is the name of the cache backend within the library (leave as-is)
region_name = 'yosai_dpcache'

# redis server connection settings:
region_arguments = {
    'url': '127.0.0.1',
    'host': 'localhost',
    'port': 6379
}

cache_handler = DPCacheHandler(ttl=ttl,
                               region_name=region_name,
                               backend='yosai_dpcache.redis',
                               region_arguments=region_arguments)
```

### Persistence

You have to register a persistent data store, such as a database, that Yosai
will request user credentials and authorization information from.  A fully
operational relational data store has been created for you to help you get
started:  ``yosai_alchemystore``.  ``yosai_alchemystore`` uses the SQLAlchemy ORM
to interface with an underlying relational database.  

Install yosai_alchemystore from PyPI using pip:
```bash
pip install yosai_alchemystore
```

Just as with ``yosai_dpcache``, ``yosai_alchemystore`` is configured either using
a settings file + env variable or by instantiating an instance with a settings
argument. For quickstart purposes, pass the database connection string
as an argument.

You'll need to decide what kind of database to use.  For testing, you could
run a sqlite database but for production you would use postgresql.   You could
find a python script within the yosai_alchemystore repo, ``create_populate_db.py``,
 that would populate a sqlite database with test data, storing it in the /conf
directory.

```Python

from yosai_alchemystore import AlchemyAccountStore

# this is the syntax of a connection string recognized by SQLAlchemy for Postgresql:
db_url = 'postgres://username:password@localhost:5432/database'

account_store = AlchemyAccountStore(db_url=db_url)

realm = AccountStoreRealm(name='DefaultRealm',
                          account_store=account_store)

```

## Instantiate

Altogether, here is how you instantiate an instance of Yosai.  

```Python
    from yosai_dpcache.cache import DPCacheHandler
    from yosai_alchemystore import AlchemyAccountStore
    from yosai.core import SecurityUtils, AccountStoreRealm

    # time values are denominated in seconds:
    ttl = {
        'absolute_ttl': 3600,
        'credentials_ttl': 300,
        'authz_info_ttl': 1800,
        'session_absolute_ttl': 1800
    }

    # this is the name of the cache backend within the library (leave as-is)
    region_name = 'yosai_dpcache'

    # redis server connection settings:
    region_arguments = {
        'url': '127.0.0.1',
        'host': 'localhost',
        'port': 6379
    }

    cache_handler = DPCacheHandler(ttl=ttl,
                                   region_name=region_name,
                                   backend='yosai_dpcache.redis',
                                   region_arguments=region_arguments)


    # this is the syntax of a connection string recognized by SQLAlchemy for
    # Postgresql:
    db_url = 'postgres://username:password@localhost:5432/database'

    account_store = AlchemyAccountStore(db_url=db_url)

    realm = AccountStoreRealm(name='DefaultRealm',
                              account_store=account_store)

    security_manager = NativeSecurityManager(cache_handler=cache_handler,
                                             realms=(realm,),
                                             session_schema=None)

    yosai = SecurityUtils(security_manager=security_manager)
```
!!! note ""
A Session ``marshmallow`` schema is omitted from this example.  You'd define a
schema to cache session attributes (state).


### Yosai Web

The ``yosai`` project features a ``yosai.core`` package and ``yosai.web``
integration library.

If you're using Yosai for web application development, use the ``yosai.web``
library to instantiate Yosai.  ``yosai.web`` is a derivative of ``yosai.core``,
extending it to support interactions with web request/response objects.

If you aren't using Yosai for web development, you will either use ``yosai.core``
or a derivative of it, just as ``yosai.web`` is a derivative of ``yosai.core``.

In the last step above, we instantiate a "native" yosai instance.  We could have easily
instantiated a web-enabled instance instead by replacing ``SecurityUtils`` with
``WebSecurityUtils`` and ``NativeSecurityManager`` with ``WebSecurityManager``
from ``yosai.web``:

```Python
from yosai.web import WebSecurityUtils, WebSecurityManager

security_manager = WebSecurityManager(realms=(realm,),
                                      cache_handler=DPCacheHandler(),
                                      session_attributes_schema=AttributesSchema)
yosai = WebSecurityUtils()
yosai.security_manager = security_manager
```


## Use

The following example was created to illustrate the myriad ways that you
can declare an authorization policy in an application, ranging from general
role-level specification to very specific "scoped" permissions.  The
authorization policy is as follows:

- Either a user with role membership "patient" or "nurse" may request a
  refill of a medical prescription
- A user who is granted permission to write prescriptions may obtain the
  list of pending prescription refill requests
- A user who is granted permission to write prescriptions for a specific
  patient may issue a prescription for that patient

```Python
from yosai.core import requires_role, requires_permission, requires_dynamic_permission


@requires_role(roleid_s=['patient', 'nurse'], logical_operator=any)
def request_prescription_refill(patient, prescription):
    ...


@requires_permission(['prescription:write'])
def get_prescription_refill_requests(patient):
    ...


@requires_dynamic_permission(['prescription:write:{patient.patient_id}'])
def issue_prescription(patient, prescription):
    ...

```

Note how the authorization policy is declared using yosai's authorization
decorators.  These global decorators are associated with the yosai instance
when the yosai instance is used as a context manager.  

**Always use yosai through the context manager.**

```Python

with yosai:
    issue_prescription(patient)

    for prescription in get_prescription_refill_requests(patient):
        issue_prescription(patient, prescription)

```

If you were using Yosai with a web application, the syntax would be similar
to that above but requires that a ``WebRegistry`` instance be passed as argument 
to the context manager.  The web integration library is further
elaborated upon in the Web Integration section of this documentation.

```Python

with yosai(web_registry):
    issue_prescription(patient)

    for prescription in get_prescription_refill_requests(patient):
        issue_prescription(patient, prescription)

```
