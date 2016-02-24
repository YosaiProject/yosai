<h1 align=center>🏯 Yosai</h1>
<h2 align=center>Application Security Management for Python</h2>

![alt text](http://i.imgur.com/QDhDfKN.jpg "Yosai 🏯 ")

Yosai is a security management framework.   It is a port of Apache Shiro,  written in Java and widely used today.
Yosai encompasses Authentication, Authorization, and Session Management.  It uses a highly modular architecture,
featuring a simple, intuitive API that will help develops adopt robust security management for their applications in little time.

Yosai offers developers separation of concern between security management and other aspects of any complicated system built today.  An intuitive user-developer API allows Yosai to be integrated with a system within minutes.  Yosai is a framework with well-defined interfaces between components and so it can be easily extended.

Authentication, Authorization, and Session Management that can support whatever you are looking for:

Does your system require a complicated authorization policy? Yosai supports whatever method of access control that you'll need for your system, from DAC to RBAC.

Looking for two-factor authentication?  Yosai supports X-factor authentication.

[ ![Build Status] [travis-image] ] [travis]
[ ![Release] [release-image] ] [releases]


PROJECT OVERVIEW
-----------------------------------------------------------------------
Please, first familiarize yourself with [Apache Shiro](http://shiro.apache.org/).  It is a remarkable system.

Today, no such open-sourced security framework like Shiro exists for the Python community.  There's an unmet need for one.  Shiro has been battle tested.  Let's learn from history by porting the java source.  Then, we'll refactor the source using techniques and libraries available in Python, using expertise from this great development community.

I am porting the [v2.0-alpha source code](http://svn.apache.org/repos/asf/shiro/branches/2.0-api-design-changes/)


WORD ORIGIN:  Yosai
-----------------------------------------------------------------------
In Japanese, the word Shiro translates to "Castle".  Yosai translates to "Fortress"🏯  . Like the words, the security platforms are similiar in meaning yet not the same.



PROJECT STATUS
==============

12/22/2015
---------------------
Yosai.core testing is complete.

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

* port of Shiro's /web package , used to help integrate Yosai with web applications

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





GROUP COMMUNICATION
-----------------------------------------------------------------------
Google Groups Mailing List:  https://groups.google.com/d/forum/yosai


CONTACT INFORMATION
-----------------------------------------------------------------------
If you would like to get involved, please contact me by:
- emailing dkcdkg at the popular "G search engine" mail
- finding me on Freenode under the nickname dowwie


APACHE SHIRO VERSION USED
-----------------------------------------------------------------------
Shiro uses subversion, which features project revision numbers.

Each sub-package is based on the latest Shiro revision at the time of unit testing.
When Yosai unit testing is completed, its revision versions will be reconciled,
using the revision that was ported and the most up to date revision.
Any materials changes discovered from revision reconciliation will be
applied to Yosai, ensuring that each subpackage reflects the most recent updates
and standarding the entire project with a common revision.

Yosai vX.X.X is as of Apache Shiro 2.0 Alpha, Revision xxxxxx


![alt text](http://i.imgur.com/Wf9UGVY.jpg "Join the Project!")
