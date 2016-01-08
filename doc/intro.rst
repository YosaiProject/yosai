

Application Security
===============================

When you write a software application, you may want to control who can use it and
how it is used.  Yosai helps you to control who can use an application and how it is used,
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
Yosai's internals.  Following is a basic preview of the API where each example
complements those prior to it.

First, a brief introduction to our main actor: the **Subject**.

Introducing:  the Subject
-------------------------
Every security related operation is performed in the context of a **Subject**.
The term "Subject" is generally synonymous with "User" except that aside from
human beings also includes non-human, system entities.  In other words, a **Subject** is
a *person* or a *thing*.


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

Authentication
--------------
In this example, we "log in" a Subject, performing password-based authentication
that raises an AuthenticationException if authentication were to fail:

.. code-block:: python

    authc_token = AuthenticationToken(username='thedude',
                                      credentials='letsgobowling')
    subject = SecurityUtils.get_subject()
    subject.login(authc_token)


Session Management
------------------
Yosai offers session management for anonymous guests or authenticated users.
In the Authentication example above, the Subject is automatically allocated a
new session in Yosai following successful authentication.  We manage
the attributes of a session through a CRUD-like series of methods:

.. code-block:: python

    subject = SecurityUtils.get_subject()

    session = subject.get_session()
    session.set_attribute('full_name', 'Jeffrey Lebowski')


Authorization
-------------
Authorization is enable in your application either by decorating methods with an
authorization check, such as in the example below, or by expicitly calling
one of Subject's access control methods.

The following example confirms whether a user has sufficient privileges to
approve a loan application.  Infomation about the syntax will come later.

.. code-block:: python

    @check_permission(['loan:approve'])
    def approve_loan_application(self, loan_application):
        loan_application.status = 'APPROVED'
        self.notify_loan_approval(loan_application)


Securing any Python Application
===============================
Yosai is designed to provide security related functionality in such a way that
it can be used with ANY kind of application: desktop apps, web apps,
 internet-enabled devices, etc.  The depth of features available to Yosai is
 simply limited by the extensions written for it.  The breadth of applications and
  frameworks using Yosai is limited by the integrations that are written for it:

Extensions
----------
Yosai consists of a core library.  To provide a complete security solution for
applications, the core library uses *extensions* -- components that extend
operations enabled by the core.  Examples of extensions include:
    - credentials repositories such as relational databases or LDAP directories
    - access control policies residing in data sources such as relational databases
    - authentication methodologies such as social-media based authentication or
      multi-factor authentication
    - caching mechanisms

Integrations
------------
Yosai is designed to enable security in such a way that it can be used with ANY
kind of application: desktop apps, web apps, internet-enabled devices, etc. Yosai
is adapted to an application through what is known as an *integration*. Developers
are encouraged to submit to the Yosai Project integrations for license-compatible
projects.


A Framework that is Ready for Customization
===========================================
Yosai is "built to contract", featuring concrete implementations of
abstract base classes that collectively define Yosai's architecture.
Developers who find Yosai's default concrete implementations unsuitable for
their needs may implement their own components according to ABC specifications
and swap components.
