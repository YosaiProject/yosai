

Application Security
===============================

When you write a software application, you may want to control who can use it and
how it is used.  Yosai helps you to control who can use an application and how it is used,
 managing state between requests.  In other words, Yosai offers authentication,
 authorization, and session management, respectively:

Authentication
--------------
    - The process of verifying identity: proving that a subject IS who "IT" claims
    to be
    - Identity is verified through some kind of credentials mechanism.

Authorization
-------------
Authorization is the process of constraining a user's interactions in a system.


Session Management
------------------
Session management of state for a user's interactions across requests

    - Managing state enables more elaborate forms of dynamic authorization to enforce
    what is known as "Least Privilege"


Securing any Python Application
===============================
Yosai is designed to provide functionality from these domains in such
a way that it can be used with ANY kind of application: desktop apps, web apps,
 internet-enabled devices, etc.


An Intuitive API without Compromising Power
===========================================
Developers can very quickly use Yosai without burdening themselves with
the internals:

Initializing Yosai
------------------
.. code-block:: python

    from yosai.core import init_yosai, SecurityUtils

    init_yosai(cache_handler=DPCacheHandler(),
               account_stores=[AlchemyAccountStore()],
               session_schema=MySessionSchema])

Authentication
--------------
.. code-block:: python

    authc_token = AuthenticationToken(username='thedude',
                                      credentials='letsgobowling')
    subject = SecurityUtils.get_subject()
    subject.login(authc_token)

Session Management
------------------

.. code-block:: python

    subject = SecurityUtils.get_subject()
    session = subject.get_session()
    session.set_attribute('full_name', 'Jeffrey Lebowski')
    session.set_attribute('username', 'thedude')

Authorization
-------------
Enable authorization in your code by decorating methods with an authorization check.
A recommended approach is to check that your user has sufficient privileges to
perform an action on a resource:

.. code-block:: python

    @check_permission(['loan:approve'])
    def approve_loan_application(self, loan_application):
        loan_application.status = 'APPROVED'
        self.notify_loan_approval(loan_application)


A Framework that is Ready for Customization
===========================================
Yosai is "built to contract", featuring concrete implementations of
Abstract Base Classes that collectively define Yosai's architecture.
Developers who find Yosai's default concrete implementations unsuitable for
their needs may implement their own components according to ABC specifications
and swap components with ease.
