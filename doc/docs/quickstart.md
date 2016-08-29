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
3. Instantiate
4. Use


## Install

First, install Yosai from PyPI using pip:
```bash
pip install yosai
```

Installing from PyPI, using pip, will install the project package that includes
``yosai.core`` and ``yosai.web``, a default configuration, and project dependencies.


## Configure

Yosai is configured through a YAML-formatted settings file.  An example of
this configuration file can be found within the [yosai.core.conf directory](https://github.com/YosaiProject/yosai/blob/master/yosai/core/conf/yosai_settings.yaml)
of the Yosai project, named ``yosai_settings.yaml``.  When you initialize a Yosai
instance, you specify as an argument *either* a file_path to a configured settings
file or an environment variable (env_var) that references the location of this file in
the system that will use Yosai:

```python
  #option 1
  yosai = Yosai(env_var='ANY_ENV_VAR_NAME_YOU_WANT')

  #option 2
  yosai = Yosai(file_path='/../../../whatever_filename_you_want.yaml')
```

### Caching

Yosai has full support for caching.  Caching is enabled by default and ought to be used.

There's a Yosai extension library, ``yosai_dpcache``, that is a
fork of Mike Bayer's popular "dogpile" projects -- core and cache -- but
customized for Yosai's serialization preferences.  Currently, ``yosai_dpcache``
supports Redis.  Pull requests to support other cache stores are welcome.

Install yosai_dpcache from PyPI using pip:
```bash
pip install yosai_dpcache
```

``yosai_dpcache`` can be configured either through the main Yosai settings file or by
manually passing in settings arguments to a DPCacheHandler class.  For QuickStart
demonstration purposes, we'll use the settings file, including the following
for a local redis server:

```bash
CACHE_HANDLER:
    init_config:
        backend: 'yosai_dpcache.redis'
        region_name: 'yosai_dpcache'
    server_config:
      redis:
        url: '127.0.0.1'
        host: 'localhost'
        port: 6379
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
a settings file or by instantiating an instance with a settings
argument. For QuickStart purposes, we'll use the settings file.

The settings file requires that ALCHEMY_STORE settings be set, if you
would like to use the ``yosai_alchemystore``.  Here is what those settings look
like for a sqlite database located with ``theuser``'s home directory.

```bash
ALCHEMY_STORE:
    engine_config:
        dialect: sqlite
        path: ////home/theuser/yosai_accounts.db
```

There is a python script within the yosai_alchemystore repo, [create_populate_db.py](https://github.com/YosaiProject/yosai_alchemystore/blob/master/yosai_alchemystore/conf/create_populate_db.py), that populates test data within a sqlite database.  


## Instantiate a Yosai instance

Altogether, here is how you QuickStart instantiate an instance of Yosai:

1) Install yosai, yosai_alchemystore, and yosai_dpcache from pypi:  
```bash
pip install yosai yosai_alchemystore yosai_dpcache
```

2) Declare an environment variable, in this case ``YOSAI_SETTINGS``, and assign
it to the location of the yaml settings file in your filesystem, such as:
```bash
export YOSAI_SETTINGS=/home/theuser/yosai_settings.yaml
```

3) Edit the yosai_settings.yaml file, updating settings for ``ALCHEMY_STORE`` and ``CACHE_HANDLER``

4) Instantiate a yosai instance:
```python
from yosai.core import Yosai

yosai = Yosai(env_var='YOSAI_SETTINGS')
```


### Quick-Starting Yosai Web

The ``yosai`` project features a ``yosai.core`` package and ``yosai.web``
integration library.

If you're using Yosai for web application development, use the ``yosai.web``
library to instantiate Yosai.  ``yosai.web`` is a derivative of ``yosai.core``,
extended to support interactions with web request/response objects.

In the Instantiation step above, we create a core Yosai instance.  We could have
instantiated a web-enabled WebYosai instance by making a small change to the
yosai_settings.yaml file, changing the security_manager configuration from

```bash
SECURITY_MANAGER_CONFIG:
    security_manager: yosai.core.NativeSecurityManager
```

to

```bash
SECURITY_MANAGER_CONFIG:
    security_manager: yosai.core.WebSecurityManager
```

and then instantiating as follows:

```python
from yosai.web import WebYosai

yosai = WebYosai(env_var='YOSAI_SETTINGS')
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
from yosai.core import Yosai

@Yosai.requires_role(roleid_s=['patient', 'nurse'], logical_operator=any)
def request_prescription_refill(patient, prescription):
    ...


@Yosai.requires_permission(['prescription:write'])
def get_prescription_refill_requests(patient):
    ...


@Yosai.requires_dynamic_permission(['prescription:write:{patient.patient_id}'])
def issue_prescription(patient, prescription):
    ...

```

Note how the authorization policy is declared using authorization-specific
decorators.  These decorators are associated with the yosai instance
passed into the context where decorated functions/methods are called:

```python

with Yosai.context(yosai):
    for prescription in get_prescription_refill_requests(patient):
        issue_prescription(patient, prescription)

```

If you were using Yosai with a web application, a context-management approach
is used again but different types of objects are passed into context, specifically a
``WebYosai`` instance and a ``WebRegistry`` instance:

```Python
with WebYosai.context(yosai, web_registry):
   # handle web request here
```
