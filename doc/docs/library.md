# Extensions and Integrations

![pluggable_security](img/pluggable_security.png)

The mission of The Yosai Project is to secure any kind of Python application.
To fulfill this mission, extensions and integrations are required.


### Extensions

As illustrated, Yosai consists of a core library.  To provide a complete security solution for applications, the core library uses *extensions* -- components that extend operations enabled by the core.  Examples of extensions include:
- credentials repositories such as relational databases or LDAP directories
- access control policies residing in data sources such as relational databases
- authentication methodologies such as social-media based authentication or
  multi-factor authentication
- caching mechanisms


### Integrations

Yosai is designed to provide security related functionality in such a way that
it can be used with ANY kind of application, including desktop apps, web apps,
internet-enabled devices, etc.

Yosai is adapted to an application through what is known as an *integration*
library.

Since a large number of applications are web-based applications, a helper
library, yosai.web, is included.  The yosai.web library should be used to help
adapt yosai to the web application of your choice, yet specific customizations
are left as an exercise for yosai integration development.  Developers are
encouraged to submit to The Yosai Project integrations for license-compatible
projects.

![batteries](img/batteries_included.png)

Yosai is being released with "batteries included" so that it may be used in a
project without requiring additional implementation (for quick starts).  To achieve this goal, two integration projects were added to The Yosai Project, providing access to a peristence layer and caching:

### Yosai AlchemyStore

An AccountStore implemented with SQLAlchemy.  The project includes a
basic RBAC data model that uses a flat, non-heirarchical design.  


### Yosai DPCache

This is an integration of the dogpile.cache project.  Yosai reduces objects
to their serializable form using Marshmallow, encodes them, and then caches.
Objects obtained from cache are de-serialized into reduced form and then
re-materialized into Yosai objects.  dogpile.cache supports Redis, Memcached,
and Riak off the shelf, featuring thread-safe asynchronous interaction using a
dogpile lock mechanism.  A “dogpile” lock is one that allows a single thread to
generate an expensive resource while other threads use the “old” value until
the “new” value is ready.

Currently, only the Redis backend has been updated and tested.  If you would like to add other backends, your pull request is welcome.  
