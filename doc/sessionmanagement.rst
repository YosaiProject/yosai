Developers use Sessions to store information about a user's interactions with 
an application across multiple requests, over a specified period of time.  Tracking
user state with sessions enables more feature-rich user experiences.  Further, 
Sessions play a major role in access control.  


Authentication, Authorization, and Session Management are Related
-----------------------------------------------------------------

Access is limited by user identity: a guest cannot perform the operations that an 
authenticated user can, and each authenticated user may perform different 
operations.  

The identity of an authenticated user is recorded in the session. 

Since access control is limited by identity, and identity is obtained
from a session, access control is considered *bound* to a session.


Session Management
------------------
Sessions are a "threat vector":  a path that an "actor" may exploit to attack
a "target" (your application).  Sessions are exploited by a process
known as hijacking.  Session Management helps to manage many of the inherent risks of 
Sessions through a series of countermeasures.  More information about these
countermeasures follows in the documentation.


Properties of a Session and Risk Countermeasures
================================================

The Session Token
-----------------
A Session Token is like a smart chip, or magnetic strip, on a credit card in
that it contains identification-- a session identifier (SessionID).  However,
unlike the elements of a credit card, the Session Token has a much shorter 
lifespan.

The SessionID is a sensitive and critical piece of information.  It uniquely
identifies a Session.  It is the Session's key in a SessionStore (cache) and 
it is the key that is sent with subsequent requests by a client (the user). 

Once an authenticated session is established, the SessionID is the client's
key to Yosai.  Therefore, it is very important that the session identifier be 
unique and very difficult to reproduce.  Yosai's default method to generate a 
SessionID is as follows::: 
    sha256(sha512(urandom(20)).digest()).hexdigest()


Temporal Risks and Countermeasures 
----------------------------------
The risk of compromising a Session increases as time passes.  To address
time-driven risks, Yosai defines temporal properties in a Session -- idle time 
and maximum allowable time to live (TTL) -- that enable "timing out".  

These properties are configured in the Yosai settings YAML file. Should 
you find their default settings unacceptable, you can easily change them.  The 
default settings are somewhat aggressive so as to minimize the risks that defaults 
may present and to encourage developers to take ownership of session time-out 
decisions.

Idle time
~~~~~~~~~
This property represents the total permissible time that a user may be inactive
in a system, or idle.  Yosai's default idle time setting for a Session 
is **5 minutes**.

Time to live
~~~~~~~~~~~~
A Session has a maximum allowable time period that it may exist.  Many computer 
systems refer to this as a TTL -- time to live.  Yosai's default 
time-to-live for a Session is **30 minutes**.


Expiration Events
~~~~~~~~~~~~~~~~~
When a Session "times out", it is considered *expired*.  When a Session is *expired*, 
it can no longer be used in Yosai, and therefore is no longer at risk of being
hijacked.

An idle timeout is detected by Yosai as it processes a request.


Stopping Sessions
-----------------
Another mechanism for rendering events useless in Yosai is to stop them.
When a subject logs out of a system, the subject's Session is stopped.  Like
an expired Session, a stopped Session can no longer be used and is consequently 
no longer at risk of being hijacked.


Session Validation
------------------
Session validation is the process of determining whether a Session has stopped
or expired.  When a session is stopped, xyz.

As discussed, there are two types of expiration:  idle and absolute-ttl.  

Keeping track of idle expiration presents challenges.  

There are two timeout thresholds: an idle timeout and absolute timeout (ttl)
the last_access_timestamp synchronized with session usage presents a 

if the duration between the last_access_timestamp and the current time exceeds
either timeout threshold, a session is considered expired

By default, Sessions are "lazy validated" in that they are validated at the time 
that [they are accessed?]. 


The Session Synchronization Design Challenge
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Keeping the last_access_timestamp synchronized with session usage presents a 
performance design challenge that you are encouraged to help improve.  Ideas
are welcome! 


"auto-touch" configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~



Session-driven Events
---------------------
At Session expiration, Yosai ties up loose ends, so to speak, through its
event-driven architecture.

[image here]


Session Initialization
----------------------
A Session can be used to manage state for a Subject regardless of whether the 
Subject has authenticated itself or remains anonymous.  Yosai initializes a 
server-side Session the moment that a Subject is instantiated: 

.. code-block:: python
    from yosai.core import SecurityUtils, UsernamePasswordToken

    # creates an "anonymous session" if the current executing subject hasn't 
    # logged in yet:
    guest = SecurityUtils.get_subject()

You can then manage state as necessary using the session, but more about that later:
.. code-block:: python
    session = guest.get_session()  # returns an anonymous session (guest)


After a user authenticates itself, Yosai creates a new session for the user.
This is done for a few reasons.  The user's access to the system changes as
the user's identity changes (from anonymous to authenticated).  A new, 
"authenticated session" replaces the "anonymous session" the moment that a 
subject is authenticated as a user:

.. code-block:: python
    from yosai.core import SecurityUtils, UsernamePasswordToken

    # creates an "anonymous session" if the current executing subject hasn't 
    # logged in yet:
    current_user = SecurityUtils.get_subject()

    authc_token = UsernamePasswordToken(username='thedude', 
                                        credentials='letsgobowling')

    # creates an "authenticated session" if login in successful, raising
    # an exception otherwise (try/except left out to simplify the example):
    current_user.login(authc_token)

.. note::
    It is recommended that the session be regenerated by the application after 
    **any** privilege level change within the associated user session.


what it offers independently and in conjunction with authorization

- Yosai usage


Session Storage
---------------
Whenever a Session is created or updated, its data is persisted to a 
storage location so that it may be accessible by the application at a later time. 
Similarly, when a Session is invalid and longer being used, it is 
deleted from storage so that the Session data store space is not exhausted (if 
you're not taking advantage of TTL expiration in your data store). 

The SessionManager implementations delegate these Create/Read/Update/Delete (CRUD) 
operations to an internal component, the SessionStore, which reflects the 
Data Access Object (DAO) design pattern.

The power of the SessionStore is that you can implement this interface to 
communicate with any data store you wish. This means your session data can 
reside in memory, on the file system, in a relational database or NoSQL data store, 
or any other location you want. You have control over persistence behavior.

Yosai features an in-memory MemorySessionStore and CachingSessionStore.  The 
CachingSessionStore is the default, and recommended, SessionStore for Yosai.


Session Serialization
---------------------


Session Dataflow
----------------


References
----------
OWASP Session Management CheatSheet:  https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

