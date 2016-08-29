# Introduction

Within this section of documentation, you will learn the fundamental concepts presented in Yosai.  More detailed documentation, including tutorials, is available in subsequent sections.

# What is Yosai?

Yosai helps you to control who can use your application and how it is used,
managing state between requests.  In other words, Yosai offers authentication,
 authorization, and session management, respectively.

## Architectural Overview: yosai.core

Yosai is a framework, allowing you to add or replace components that are designed according to documented interface specifications.  More specifically, the framework is defined using a collection of abstract base classes.

![anon_architecture](img/anon_architecture.png)

Although it is customizable, Yosai features a set of default implementations to address its most anticipated uses. It is "built to contract", featuring concrete implementations of abstract base classes that collectively define Yosai's architecture. Developers who find Yosai's default concrete implementations unsuitable for their needs may implement their own components according to ABC specifications and swap components.


# Fundamentals

## Initializing Yosai

With Yosai initialized, you can authenticate, authorize, and manage sessions.

To initialize Yosai, you must tell Yosai where to obtain its settings from.  

These settings include information such as:

- Cryptographic hashing settings for password-based authentication
- Whether caching is enabled, and if so what CacheHandler to use
- The AccountStore instance(s) from which to obtain authentication and
  authorization information
- A class defining special marshalling logic uses for server-side sessions,
  if one is required for your sessions and you are caching

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

!!! note ""
    - To properly serialize your session attributes, you will need to define
      a custom session attributes schema class containing marshalling logic,
      if your session attributes are beyond simple primitive data types available
      from python standard library.  


## Introducing: Subject

The three core services provided by Yosai are:

1. Authentication
2. Authorization
3. Session Management

These services share a common API that you will use to interact with them:  the Subject API.

Every security related operation is performed in the context of a **Subject**.
The term "Subject" is generally synonymous with "User" except that aside from
human beings also includes non-human, system entities.  In other words, a **Subject** is a *person* or a *thing*.


## Authentication

In this example, we "log in" a Subject, performing password-based authentication
that raises an AuthenticationException if authentication were to fail.

Note that the following example assumes that a ``yosai`` instance has already
been instantiated and configured with a SecurityManager.  See the ``yosai init``
documentation, further below, for how to do that.

```Python
    from yosai.core import AuthenticationToken, Yosai

    yosai = Yosai(env_var='YOSAI_SETTINGS')

    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()

        authc_token = UsernamePasswordToken(username='thedude',
                                            credentials='letsgobowling')
        subject.login(authc_token)
```

!!! note ""
    UsernamePasswordToken is a consolidation of a user account's identifying
    attributes (username) and credentials (password) submitted by a user
    during an authentication attempt


## Authorization

Authorization is conducted in your application either by decorating methods with an authorization check, such as in the example below, or by explicitly calling one of Subject's access control methods.

The following example confirms whether the user logged in above has sufficient
privileges to approve a bowling tournament application.  We illustrate what is known as the *declarative style* authorization.  Information about authorization styles can be found in the authorization documentation.

```Python
    from yosai.core import Yosai

    @Yosai.check_permission(['tournament:approve'])
    def approve_tournament_application(self, tournament_application):
        tournament_application.status = 'APPROVED'
        self.notify_approval(tournament_application)
```


## Session Management

Yosai offers session management for anonymous guests or authenticated users.
In the Authentication example above, the Subject is automatically allocated a
new session in Yosai following successful authentication.  We manage
the attributes of a session through a CRUD-like series of methods:

Note that the following example assumes that a ``yosai`` instance has already
been instantiated and configured with a SecurityManager.  See the ``yosai init``
documentation, further below, for how to do that.

```Python
    from yosai.core import Yosai

    yosai = Yosai(env_var='YOSAI_SETTINGS')

    with Yosai.context(yosai):
        subject = Yosai.get_current_subject() 
        session = subject.get_session()
        session.set_attribute('full_name', 'Jeffrey Lebowski')
```
