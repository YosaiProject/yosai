# Sessions and Session Management

![sessionman](img/sessionmanagement.png)

Use Sessions to track the state of a user's interactions with your application across multiple requests, over a specified period of time.  Tracking user state with Sessions enables more feature-rich user experiences.  Further, Sessions play a major role in access control.

Session Management involves creating, reading, updating, and deleting of Sessions and Session attributes, and validating Sessions.

Yosai's `SessionManager` uses a `CachingSessionStore` to cache sessions. If you are not caching sessions, you you are either using in-memory session storage  (the `MemorySessionStore`) or using your own custom SessionStore, which is beyond the scope of consideration in this documentation.


## Authentication, Authorization, and Session Management are Related

Access is limited by user identity: a guest cannot perform the operations that an authenticated user can, and each authenticated user may perform different operations.

The identity of an authenticated user is recorded in the Session.

Since access control is limited by identity, and identity is obtained from a Session, access control is considered *bound* to a Session.


## Properties of a Session , Session Risk, and Risk Countermeasures

Sessions are a "threat vector":  a path that an "actor" may exploit to attack a "target" (your application).  Sessions are exploited by a process known as hijacking.  Session Management helps to manage many of the inherent risks of Sessions through a series of countermeasures.  More information about these countermeasures follows in the documentation.


### The Session Token

A Session Token is like a smart chip, or magnetic strip, on a credit card in that it contains identification-- a session identifier (SessionID).  However, unlike the elements of a credit card, the Session Token has a much shorter lifespan.

The `SessionID` is a sensitive and critical piece of information.  It uniquely identifies a Session.  It is the Session's key in a SessionStore (cache) and it is the key that is sent with subsequent requests by a client (the user).

Once an authenticated session is established, the `SessionID` is the client's key to Yosai.  Therefore, it is very important that the session identifier be unique and very difficult to reproduce.  

Yosai's default method to generate a `SessionID` is as follows:
`sha256(sha512(urandom(20)).digest()).hexdigest()`


### Temporal Risks and Countermeasures

The risk of compromising a Session increases as time passes.  To address time-driven risks, Yosai defines temporal properties in a Session -- idle time and maximum allowable time to live (TTL) -- that enable "timing out" of Sessions.

When a Session "times out", it is considered **expired**.  When a Session is **expired**, it can no longer be used in Yosai, and therefore is no longer at risk of being hijacked.

The timeout thresholds are configured in the Yosai settings YAML file. Should you find their default settings unacceptable, you can easily change them.  The default settings are somewhat aggressive so as to minimize the risks that defaults may present and to encourage developers to take ownership of session time-out decisions.


### Idle time

![idle_timeout](img/idle.png)

This property represents the total permissible time for a user to be inactive in a system, or idle.  Picture idle timeout as an hourglass that is turned over and reset periodically. The way that idle time is reset is by updating the Session's `last_access_time` attribute.  As to when the `last_access_time` is updated depends on what "auto_touch" has been configured to or whether you've chosen an alternative time to touch than the default (per-access).

A `DefaultNativeSessionManager` has an attribute, "auto_touch", that when set to True will allow the updating of a Session's `last_access_time` attribute to the current time, whenever a session is accessed, following Session validation. As mentioned, when a Session should be touched depends on the type of application you are developing and thus auto_touch is a configurable feature.  When a Session is obtained from the SessionStore, it is immediately validated.  Should the validation not raise any exceptions, and if auto_touch is True, the Session will be "touched".  Touching a Session is the process of flipping and resetting the hourglass, so to speak, by updating the `last_access_time` attribute of the Session.

Yosai's default idle time setting for a Session is **5 minutes**.


### Time to live

![ttl](img/ttl.png)

A Session has a maximum allowable time period that it may exist.  It is the final countdown until a Session is expired. It cannot be reset, unlike idle timeout. Many computer systems refer to this as a TTL -- time to live.  Yosai's default time-to-live for a Session is **30 minutes**.


### Stopping Sessions

Aside from expirations, another mechanism for rendering Sessions useless in is **stopping** them.  When a subject logs out of a system, the subject's Session is stopped.  Like an expired Session, a **stopped** Session can no longer be used and is consequently no longer at risk of being hijacked.


### Session Validation

Session Validation is the process of determining whether a Session has stopped or expired.  When a session has stopped or expired, it is considered **invalid**.

A Session expires when the time duration between the current time and the last recorded time that a Session was accessed exceeds either timeout threshold.

Keeping track of idle expiration presents performance challenges.  Therefore, Sessions are validated _only_ when they are accessed (i.e. subject.get_session()).

the last_access_timestamp synchronized with session usage presents a

if the duration between the last_access_timestamp and the current time exceeds either timeout threshold, a session is considered expired

By default, Sessions are "lazy validated" in that they are validated at the time that [they are accessed?].

As discussed in an earlier section above, access control is _bound_ to a Session. Since access control is _bound_ to a Session, when a Session is invalidated so too does the authorization information cached for the Session.  Invalid authorization information is cleared from cache through event handling.


### Idle Timeout Edge Case
Monitoring for idle timeout increases the complexity of Session Management.
As discussed, Session validation taxes the performance of an application and
therefore does not run before every authorization check.  Instead, validation
is designed to maximize utility for the most popular use case-- one where the
subject instance has a short life span in memory and sessions validate when
they are accessed.

Therefore, it is recommended that you release a Subject instance for garbage
collection between requests.


## The Session Synchronization Design Challenge

Keeping the last_access_timestamp synchronized with session usage presents a performance design challenge that you are encouraged to help improve.  Ideas are welcome!


## Session Invalidation

By default, whenever Yosai detects an invalid session, it attempts to delete it from the underlying session data store via the SessionStore.delete(session) method.  However, should you decide not to automatically delete invalid sessions, you can easily opt-out of this process.  For example, if your application uses a SessionStore that backs a queryable data store, perhaps your dev team wants old or invalid sessions to be available for a certain period of time. Storing invalid sessions would allow you to run queries against the data store to see, for example, how many sessions a user has created over the last week, or the average duration of a user's sessions, or similar reporting-type queries.

At Session expiration, Yosai ties up loose ends, so to speak, through its event-driven architecture.


## Session Usage


### Session Initialization

A Session can be used to manage state for a Subject regardless of whether the Subject has authenticated itself or remains anonymous.  Yosai initializes a server-side Session when a Subject is instantiated.

```Python
from yosai.core import Yosai, UsernamePasswordToken

# creates an "anonymous session" if the current executing subject hasn't
# logged in yet:
yosai = Yosai(env_var='YOSAI_SETTINGS')

with Yosai.context(yosai):
  guest = Yosai.get_current_subject()  # session is created in the process
  session = subject.get_session()
```
After a user authenticates itself, Yosai creates a new session for the user. This is done for a few reasons.  The user's access to the system changes as the user's identity changes (from anonymous to authenticated).  A new, "authenticated session" replaces the "anonymous session" the moment that a subject is authenticated as a user:

```Python
from yosai.core import Yosai, UsernamePasswordToken

with Yosai.context(yosai):
  # creates an "anonymous session" if the current executing subject hasn't
  # logged in yet:
  subject = Yosai.get_current_subject()

  authc_token = UsernamePasswordToken(username='thedude',
                                      credentials='letsgobowling')

  # creates an "authenticated session" if login in successful, raising
  # an exception otherwise (try/except left out to simplify the example):
  subject.login(authc_token)
```

!!! note ""
    It is recommended that the session be regenerated by the application after     **any** privilege level change within the associated user session.


## Session Storage

Whenever a Session is created or updated, its data is persisted to a storage location so that it may be accessible by the application at a later time. Similarly, when a Session is invalid and longer being used, it is deleted from storage so that the Session data store space is not exhausted (if you're not taking advantage of TTL expiration in your data store).

The SessionManager implementations delegate these Create/Read/Update/Delete (CRUD) operations to an internal component, the SessionStore, which reflects the Data Access Object (DAO) design pattern.

The power of the SessionStore is that you can implement this interface to communicate with any data store you wish. This means your session data can reside in memory, on the file system, in a relational database or NoSQL data store, or any other location you want. You have control over persistence behavior.

Yosai features an in-memory MemorySessionStore and CachingSessionStore.  The CachingSessionStore is the default, and recommended, SessionStore for Yosai.


## Session Events

An Event is emitted to the singleton EventBus, in Yosai, when a Session is _started_, _stopped_, or _expired_.  If you would like to learn more about Event processing, please refer to the documentation about Event Processing.

Events are communicated using a publish-subscribe paradigm.  In the case of Sessions, a `SessionEventHandler` publishes an event to a channel (an internal Event Bus). The EventBus relays an event to consumers who have subscribed to the event's topic. It relays the event by calling the callback method registered for a consumer, using the event payload as its argument(s).

The following table lists the Session-related events and who the subscriber(s) are:

Event Topic    | Subscriber(s)
-------------- | -------------
SESSION.START  | EL           
SESSION.STOP   | MRA, EL      
SESSION.EXPIRE | MRA, EL      

- MRA = `yosai.core.authz.authz.ModularRealmAuthorizer`
- SEH = `yosai.core.session.session.SessionEventHandler`


### Example:  SESSION.EXPIRE Event Processing

At Yosai initialization, `yosai.core.authz.authz.ModularRealmAuthorizer` subscribes to a few event topics, one of which is 'SESSION.EXPIRE'. When it subscribes to the 'SESSION.EXPIRE' topic, it registers a callback method, `session_clears_cache`.  This callback method is called by the EventBus whenever a 'SESSION.EXPIRE' event is emitted to the bus.

A `SESSION.EXPIRE` event is emitted by a `yosai.core.session.session.SessionEventHandler` when Session Validation has recognized a Session as expired.

As of yosai.core v0.1.0, the `ModularRealmAuthorizer` and `EventLogger` are the two subscribers of the `SESSION.EXPIRE` topic (see table above).  The callback method registered for each subscriber is called in an arbitrary, sequential fasion (PyPubSub design) when a SessionEventHandler emits a SESSION.EXPIRE event to the Eventbus.

Here is an example of an `expired-session` event processing through Yosai, omitting event logging processing:

![](img/session_event_processing.png)


# Session Tutorial

In this tutorial, you will learn how to use the Session API to perform server-side session management.  We'll use a shopping cart example to illustrate how to manage state using a Session object.  You will learn how to:

1. define marshalling logic required to properly (de)serialize custom objects
2. manage sessions using Yosai's Session API, including:
  - get_attribute
  - set_attribute
  - remove_attribute

This is *not* a primer on how to write your own e-commerce shopping cart application.  This example is intended to illustrate the Session API.  This ShoppingCart uses a really stripped down, dumb model intended to show you how to control the marshalling of custom
objects.

Marshalling supports standard object types from the standard library.  When you use objects other than standard primitives, such as objects from the collections library,
you'll need to control conversion of your objects to supported data types, and vice versa, by implementing __setstate__ and __getstate__ methods within your serializables:

```Python

ShoppingCartItem = collections.namedtuple('ShoppingCartItem', 'upc title')

class ShoppingCart:
    def __init__(self):
        self.basket = collections.defaultdict(int)

    def add_item(self, item, quantity=1):
        """
        :param item: a ShoppingCartItem namedtuple
        :type quantity: int
        """
        self.basket[item] += quantity

    def remove_item(self, item):
        """
        :param item: a ShoppingCartItem namedtuple
        """
        self.basket.pop(item)

    def __getstate__(self):
        # neither defaultdict nor tuple key is supported for serialization
        # so we must convert them:
        return {'basket': {'{0}|{1}'.format(key.upc, key.title): value
                           for key, value in self.basket.items()}}

    def __setstate__(self, state):
        self.basket = collections.defaultdict(int)
        for key, value in state['basket'].items():
            keys = key.split("|")
            self.basket[ShoppingCartItem(upc=keys[0], title=keys[1])] = value


```

You are ready to initialize Yosai with shopping-cart enabled session management
capabilities.  Simply pass the serializable during Yosai initialization within
a list:

```Python
    yosai = Yosai(env_var='YOSAI_SETTINGS',
                  session_attributes=[ShoppingCart])
```

Here's one way you could interact with the shopping cart in your application using
Yosai session management:

### Shopping Cart Manager

```Python
class ShoppingCartSessionManager:

    @staticmethod
    def list_items(session):
        shopping_cart = session.get_attribute('shopping_cart')
        if shopping_cart:
            return shopping_cart.items()
        return None

    @staticmethod
    def add_item(session, item, quantity=1):
        """
        :param item: a ShoppingCartItem namedtuple
        """
        shopping_cart = session.get_attribute('shopping_cart')
        if shopping_cart:
            shopping_cart.add_item(item, quantity)
        else:
            shopping_cart = ShoppingCart()
        session.set_attribute('shopping_cart', shopping_cart)


    @staticmethod
    def remove_item(session, item):
        shopping_cart = session.get_attribute('shopping_cart')
        if shopping_cart:
            shopping_cart.remove_item(item)
            session.set_attribute('shopping_cart', shopping_cart)
```

Let's now see all of our objects in action. We'll add items to the shopping cart
and then remove one.

### Operation 1:  Add four items to the shopping cart

```Python
    yosai = Yosai(env_var='YOSAI_SETTINGS',
                  session_attributes=[ShoppingCart])

    cart = ShoppingCartSessionManager

    with Yosai.context(yosai):
      subject = Yosai.get_current_subject()
      session = subject.get_session()

      # could easily use functools.partial for this, but keeping it explicit
      # for the example so as to not confuse:
      cart.add_item(session, '0043000200216', 4)
      cart.add_item(session, '016000119772', 1)
      cart.add_item(session, '52159012038', 3)
      cart.add_item(session, '00028400028196', 1)

      cart.list_items(session)
```

### Operation 2:  Remove an item from the shopping cart

```Python
    yosai = Yosai(env_var='YOSAI_SETTINGS',
                  session_attributes=[ShoppingCart])

    cart = ShoppingCartSessionManager(session)

    with Yosai.context(yosai):
      subject = Yosai.get_current_subject()
      session = subject.get_session()

      cart.remove_item(session, '00028400028196')

      cart.list_items(session)
```
###[Here](https://github.com/YosaiProject/yosai/blob/master/doc/docs/samplecode/sessionmanagement.py) is a fully working example of the code shared above.

## References
[OWASP Session Management CheatSheet]( https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
