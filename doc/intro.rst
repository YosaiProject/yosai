

Application Security
===============================

Yosai helps you to control who can use an application and how it is used,
managing state between requests.  In other words, Yosai offers authentication,
 authorization, and session management, respectively:

Authentication
--------------
Authentication is the process of verifying identity, proving that a subject IS
who "IT" claims to be. Identity is verified through some kind of credentials
mechanism.

Authorization
-------------
Authorization is the process of constraining a user's access to sensitive data
and interactions in a system in accordance with an access control policy.

Session Management
------------------
Session Management controls a user's state in a system, across requests.


An Intuitive API
===========================================
Developers can use Yosai without burdening themselves with knowledge about
Yosai's internals.  Following is a basic preview of Yosai's API. Each example
complements those it follows.


Introducing: Subject
-------------------------
First, a brief introduction to our main actor: the **Subject**.

Every security related operation is performed in the context of a **Subject**.
The term "Subject" is generally synonymous with "User" except that aside from
human beings also includes non-human, system entities.  In other words, a **Subject** is
a *person* or a *thing*.

Onward..

Initializing Yosai
------------------
Initialize Yosai in the namespace that requires security.  With Yosai
initialized, you can authenticate, authorize, and manage sessions.

.. code-block:: python

    from yosai.core import SecurityUtils

    realm = AccountStoreRealm()

    SecurityUtils.init_yosai(cache_handler=DPCacheHandler(),
                             realms=(realm,),
                             session_schema=MySessionSchema)

.. note::
    - CacheHandler is a Yosai extension
    - The underlying AccountStore that is referenced by the AccountStoreRealm
      object is also a Yosai extension
    - MySessionSchema is a ``marshmallow`` Schema class


Authentication
--------------
In this example, we "log in" a Subject, performing password-based authentication
that raises an AuthenticationException if authentication were to fail:

.. code-block:: python

    from yosai.core import SecurityUtils, AuthenticationToken

    authc_token = UsernamePasswordToken(username='thedude',
                                      credentials='letsgobowling')
    subject = SecurityUtils.get_subject()
    subject.login(authc_token)

.. note::
    UsernamePasswordToken is a consolidation of a user account's identifying
    attributes (username) and credentials (password) submitted by a user
    during an authentication attempt


Session Management
------------------
Yosai offers session management for anonymous guests or authenticated users.
In the Authentication example above, the Subject is automatically allocated a
new session in Yosai following successful authentication.  We manage
the attributes of a session through a CRUD-like series of methods:

.. code-block:: python

    from yosai.core import SecurityUtils

    subject = SecurityUtils.get_subject()

    session = subject.get_session()
    session.set_attribute('full_name', 'Jeffrey Lebowski')


Authorization
-------------
Authorization is conducted in your application either by decorating methods with an
authorization check, such as in the example below, or by expicitly calling
one of Subject's access control methods.

The following example confirms whether the user logged in above has sufficient
privileges to approve a bowling tournament application.  Infomation about the
syntax will come later.

.. code-block:: python

    from yosai.core import check_permission

    @check_permission(['tournament:approve'])
    def approve_tournament_application(self, tournament_application):
        tournament_application.status = 'APPROVED'
        self.notify_approval(tournament_application)


Architectural Overview: yosai.core
==================================
Yosai is "built to contract", featuring concrete implementations of
abstract base classes that collectively define Yosai's architecture.
Developers who find Yosai's default concrete implementations unsuitable for
their needs may implement their own components according to ABC specifications
and swap components.

The following diagram illustrates yosai.core architectural components
and their relationships.  End-users of Yosai -- those who aren't conducting their
own customizations of the framework -- interact primarily with the API provided
by the Subject component at the top.


Securing any Python Application
===============================

Extensions
----------
As illustrated, Yosai consists of a core library.  To provide a complete security
solution for applications, the core library uses *extensions* -- components that extend
operations enabled by the core.  Examples of extensions include:
    - credentials repositories such as relational databases or LDAP directories
    - access control policies residing in data sources such as relational databases
    - authentication methodologies such as social-media based authentication or
      multi-factor authentication
    - caching mechanisms

Integrations
------------
Yosai is designed to provide security related functionality in such a way that
it can be used with ANY kind of application, including desktop apps, web apps,
internet-enabled devices, etc.

Yosai is adapted to an application through what is known as an *integration*
library. Developers are encouraged to submit to The Yosai Project integrations
for license-compatible projects.
