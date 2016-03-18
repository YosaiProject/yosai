# Yosai
## Security Framework for Python Applications

![yosai_logo](/doc/docs/img/yosai_logo_with_title.png)

Project web site:  http://yosaiproject.github.io/yosai


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



# Batteries are Included

![batteries](/doc/docs/img/batteries_included.png)

Yosai is a framework, which means you have to plug in a few things to get it to
work.  Although Yosai is a framework, it features a library of default components
that are tested and ready to "plug in".




WORD ORIGIN:  Yosai
-----------------------------------------------------------------------

In Japanese, the word Shiro translates to "Castle".  Yosai translates to "Fortress"🏯  . Like the words, the frameworks are similar yet different.



Yosai is being released with batteries included so that it may be used in a
project without requiring additional module implementation.  To achieve this goal:

* two integration projects were added to The Yosai Project, providing
access to a peristence layer and caching:

###I) Yosai AlchemyStore
An AccountStore implemented with SQLAlchemy.  The project includes a
basic RBAC data model that uses a flat, non-heirarchical design.  

###II) Yosai DPCache
This is an integration of the dogpile.cache project.  Yosai reduces objects
to their serializable form using Marshmallow, encodes them, and then caches.
Objects obtained from cache are de-serialized into reduced form and then
re-materialized into Yosai objects.  dogpile.cache supports Redis, Memcached,
and Riak off the shelf, featuring thread-safe asynchronous interaction using a
dogpile lock mechanism.  A “dogpile” lock is one that allows a single thread to
generate an expensive resource while other threads use the “old” value until
the “new” value is ready.

Currently, the Redis integration has been tested.  If you would like to
add other backends, your pull request is welcome.  Note that dogpile.cache's
other backends are not compatible from off the shelf.

PyTest Coverage stats (ao 12/22/2015):

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
