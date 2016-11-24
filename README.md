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

- Enables Role-Based Access Control policies through permission-level and role-level
  access control
- Two-Factor Authentication, featuring Time-based One-Time Passwords
- Native Support for Caching and Serialization
- A Complete Audit Trail of Events
- Batteries Included:  Extensions Ready for Use
- "RunAs" Administration Tool
- Event-driven Processing
- Ready for Web Integration


## Python 3 Supported

Yosai requires Python 3.4 or newer. There are no plans to support python2
due to anticipated optimizations that require newer versions of python.


## Installation

First, install Yosai from PyPI using pip:
    ``pip install yosai``

Installing from PyPI, using pip, will install the project package that includes
``yosai.core`` and ``yosai.web``, a default configuration, and project dependencies.


## Basic Authentication:  UsernamePassword
```Python
yosai = Yosai(env_var='YOSAI_SETTINGS')

with Yosai.context(yosai):
    current_user = Yosai.get_current_subject()

    authc_token = UsernamePasswordToken(username='thedude',
                                        credentials='letsgobowling')

    try:
        current_user.login(authc_token)
    except AuthenticationException:
        # insert here
```


## Two-Factor Authentication:  UsernamePassword and TOTP

### 2FA Step 1:  UsernamePassword
```Python
yosai = Yosai(env_var='YOSAI_SETTINGS')


with Yosai.context(yosai):
    current_user = Yosai.get_current_subject()

    userpass_token = UsernamePasswordToken(username='thedude',
                                        credentials='letsgobowling')

    try:
        current_user.login(userpass_token)
    except AdditionalAuthenticationRequired: 
        # communicate a two-factor token request to user         
    except IncorrectCredentialsException: 
        # user failed to authenticate 
```


### 2FA Step 2:  TOTP

```Python
yosai = Yosai(env_var='YOSAI_SETTINGS')


with Yosai.context(yosai):
    current_user = Yosai.get_current_subject()

    totp_token = TOTPToken(user_provided_token) 

    try:
        current_user.login(totp_token)
    except IncorrectCredentialsException: 
        # user failed to authenticate 

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

Note how the authorization policy is declared using yosai's authorization
decorators.  These global decorators are associated with the yosai instance
when the yosai instance is used as a context manager.

```Python

with Yosai.context(yosai):
    issue_prescription(patient)

    for prescription in get_prescription_refill_requests(patient):
        issue_prescription(patient, prescription)
```

If you were using Yosai with a web application, the syntax would be similar
to that above but requires that a ``WebRegistry`` instance be passed as
as argument to the context manager.  The web integration library is further
elaborated upon in the Web Integration section of this documentation.

```Python

with WebYosai.context(yosai, web_registry):
	...
```

This is just a README file.  Please visit [the project web site](http://yosaiproject.github.io/yosai) to get a full overview.


# WORD ORIGIN:  Yosai

In Japanese, the word Shiro translates to "Castle".  Yosai translates to "Fortress".
Like the words, the frameworks are similar yet different.


# Development Status

Yosai v0.3 was released Nov 24, 2016. 

This release includes:
1) General support for second factor authentication (2FA)
2) A complete time-based one time password authentication solution (TOTP)
3) Configurable rate limiting / account locking
4) Significant refactoring / optimizatio

Please see the [release notes](https://yosaiproject.github.io/yosai/devstatus/)
for details about that release.

v0.3 test coverage stats (ao 11/24/2016):

|Name                                         |Stmt |Miss|Cover |
|:---------------------------------------------|:-----:|:----:|:------:|
| yosai/core/account/account.py               | 5   | 1  | 80%  |
| yosai/core/authc/authc.py                   | 196 | 33 | 83%  |
| yosai/core/authc/authc_settings.py          | 19  | 2  | 89%  |
| yosai/core/authc/credential.py              | 51  | 5  | 90%  |
| yosai/core/authc/strategy.py                | 40  | 0  | 100% |
| yosai/core/authz/authz.py                   | 199 | 28 | 86%  |
| yosai/core/concurrency/concurrency.py       | 16  | 4  | 75%  |
| yosai/core/conf/yosaisettings.py            | 59  | 7  | 88%  |
| yosai/core/event/event.py                   | 28  | 0  | 100% |
| yosai/core/exceptions.py                    | 40  | 0  | 100% |
| yosai/core/logging/formatters.py            | 35  | 0  | 100% |
| yosai/core/logging/slogging.py              | 5   | 0  | 100% |
| yosai/core/mgt/mgt.py                       | 285 | 5  | 98%  |
| yosai/core/mgt/mgt_settings.py              | 37  | 2  | 95%  |
| yosai/core/realm/realm.py                   | 186 | 11 | 94%  |
| yosai/core/serialize/marshalling.py         | 14  | 8  | 43%  |
| yosai/core/serialize/serialize.py           | 24  | 0  | 100% |
| yosai/core/serialize/serializers/cbor.py    | 53  | 3  | 94%  |
| yosai/core/serialize/serializers/json.py    | 56  | 41 | 27%  |
| yosai/core/serialize/serializers/msgpack.py | 49  | 29 | 41%  |
| yosai/core/session/session.py               | 547 | 63 | 88%  |
| yosai/core/session/session_settings.py      | 13  | 1  | 92%  |
| yosai/core/subject/identifier.py            | 60  | 3  | 95%  |
| yosai/core/subject/subject.py               | 451 | 22 | 95%  |
| yosai/core/utils/utils.py                   | 137 | 87 | 36%  |
| yosai/web/exceptions.py                     | 7   | 0  | 100% |
| yosai/web/mgt/mgt.py                        | 74  | 1  | 99%  |
| yosai/web/registry/registry_settings.py     | 5   | 0  | 100% |
| yosai/web/session/session.py                | 143 | 2  | 99%  |
| yosai/web/subject/subject.py                | 162 | 4  | 98%  |
|---------------------------------------------|-----|----|------|

# GROUP COMMUNICATION
Google Groups Mailing List:  https://groups.google.com/d/forum/yosai


# CONTACT INFORMATION
Darin Gordon is the author of Yosai  http://www.daringordon.com


# LICENSE
Licensed under the Apache License, Version 2.0 (the "License"); you may not
use any portion of Yosai except in compliance with the License.
Contributors agree to license their work under the same License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
