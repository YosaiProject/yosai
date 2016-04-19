
![yosai_logo](/doc/docs/img/yosai_logo_with_title.png)

# A Security Framework for Python Applications

## Project web site:  http://yosaiproject.github.io/yosai


# What is Yosai

Yosai is a "security framework" that features authentication, authorization, and session
management from a common, intuitive API.  

![authc_authz_sess](/doc/docs/img/authc_authz_sess.png)

Yosai is based on Apache Shiro, written in Java and widely used today.


# Yosai is a Framework

![framework](/doc/docs/img/yosai_framework.png)

It is a framework that is is designed in such a way that it can be used to secure
a variety of python applications, not just web applications.  This is accomplished
by completely decoupling security-related services from the rest of an application
and writing adapters for each specific type of client.  


# Key Features

- Enables Role-Based Access Control Policies
- Native Support for Caching, Including Serialization
- A Complete Audit Trail of Events
- Batteries Included:  Extensions Ready for Use
- "RunAs" Administration Tool
- Event-driven Processing
- Ready for Web Integration

## Python 3 Supported

Yosai v0.1.0 requires Python 3.4 or newer. There are no plans to support python2 
due to anticipated optimizations that require newer versions of python.


## Installation

First, install Yosai from PyPI using pip:
    ``pip install yosai``

Installing from PyPI, using pip, will install the project package that includes
``yosai.core`` and ``yosai.web``, a default configuration, and project dependencies.


## Authentication Example
```Python

with yosai:
    current_user = yosai.subject

    authc_token = UsernamePasswordToken(username='thedude',
                                        credentials='letsgobowling')

    try:
        current_user.login(authc_token)
    except AuthenticationException:
        # insert here
```

## Authorization Example

The following example was created to illustrate the myriad ways that you
can declare an authorization policy in an application, ranging from general
role-level specification to very specific "scoped" permissions.  The
authorization policy for this example is as follows:

- Either a user with role membership "patient" or "nurse" may request a
  refill of a medical prescription
- A user who is granted permission to write prescriptions may obtain the
  list of pending prescription refill requests
- A user who is granted permission to write prescriptions for a specific
  patient may issue a prescription for that patient

```Python
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

```Python

with yosai:
    issue_prescription(patient)

    for prescription in get_prescription_refill_requests(patient):
        issue_prescription(patient, prescription)
```

If you were using Yosai with a web application, the syntax would be similar
to that above but requires that a ``WebRegistry`` instance be passed as
as argument to the context manager.  The web integration library is further
elaborated upon in the Web Integration section of this documentation.

```Python

with yosai(web_registry):
    issue_prescription(patient)

    for prescription in get_prescription_refill_requests(patient):
        issue_prescription(patient, prescription)

```

This is just a README file.  Please visit [the project web site](http://yosaiproject.github.io/yosai) to get a full overview.


# WORD ORIGIN:  Yosai

In Japanese, the word Shiro translates to "Castle".  Yosai translates to "Fortress".
Like the words, the frameworks are similar yet different.


# Development Status

yosai.core coverage stats (ao 12/22/2015):

|Name                                    | Stmts |Miss  | Cover |
|:---------------------------------------|:-----:|:----:|:------:|
| yosai/core/account/account.py          | 23  | 1  | 96%  |
| yosai/core/authc/authc.py              | 167 | 14 | 92%  |
| yosai/core/authc/authc_account.py      | 65  | 12 | 82%  |
| yosai/core/authc/context.py            | 39  | 2  | 95%  |
| yosai/core/authc/credential.py         | 56  | 5  | 91%  |
| yosai/core/authc/decorators.py         | 26  | 0  | 100% |
| yosai/core/authc/strategy.py           | 98  | 6  | 94%  |
| yosai/core/authz/authz.py              | 381 | 36 | 91%  |
| yosai/core/authz/decorators.py         | 18  | 0  | 100% |
| yosai/core/conf/yosaisettings.py       | 53  | 1  | 98%  |
| yosai/core/context/context.py          | 54  | 12 | 78%  |
| yosai/core/event/event.py              | 87  | 5  | 94%  |
| yosai/core/exceptions.py               | 165 | 1  | 99%  |
| yosai/core/logging/s_logging.py        | 77  | 56 | 27%  |
| yosai/core/mgt/mgt.py                  | 380 | 7  | 98%  |
| yosai/core/mgt/mgt_settings.py         | 9   | 1  | 89%  |
| yosai/core/realm/realm.py              | 151 | 9  | 94%  |
| yosai/core/serialize/serialize.py      | 98  | 31 | 68%  |
| yosai/core/session/session.py          | 743 | 55 | 93%  |
| yosai/core/session/session_gen.py      | 10  | 0  | 100% |
| yosai/core/session/session_settings.py | 17  | 1  | 94%  |
| yosai/core/subject/identifier.py       | 65  | 4  | 94%  |
| yosai/core/subject/subject.py          | 441 | 25 | 94%  |
| yosai/core/utils/utils.py              | 66  | 38 | 42%  |
|-------  -------------------------------|-----|----|------|

# GROUP COMMUNICATION
Google Groups Mailing List:  https://groups.google.com/d/forum/yosai


# CONTACT INFORMATION
If you would like to get involved, please contact me by:
- emailing dkcdkg at gmail
- finding me on Freenode under the nickname dowwie


# LICENSE
Licensed under the Apache License, Version 2.0 (the "License"); you may not use any portion of  Yosai except in compliance with the License. Contributors agree to license their work under the same License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
