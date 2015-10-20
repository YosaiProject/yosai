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

08/01/2015 Status
-----------------
Finished Unit Testing:
    - conf
    - authc
    - authz
    - event
    - realm
    - serialize
    - session

Pytest unit testing coverage stats are as follows:

|Name                                  | Stmts |Miss  | Cover |
|:--------------------------------------|:-------:|:------:|:-------:|
| yosai/__init__.py                    | 43    | 0    | 100%  |
| yosai/account/__init__.py            | 0     | 0    | 100%  |
| yosai/account/abcs.py                | 26    | 8    | 69%   |
| yosai/authc/__init__.py              | 0     | 0    | 100%  |
| yosai/authc/abcs.py                  | 64    | 21   | 67%   |
| yosai/authc/authc.py                 | 151   | 10   | 93%   |
| yosai/authc/authc_account.py         | 59    | 10   | 83%   |
| yosai/authc/context.py               | 39    | 2    | 95%   |
| yosai/authc/credential.py            | 48    | 5    | 90%   |
| yosai/authc/strategy.py              | 98    | 6    | 94%   |
| yosai/authz/__init__.py              | 0     | 0    | 100%  |
| yosai/authz/abcs.py                  | 53    | 18   | 66%   |
| yosai/authz/authz.py                 | 335   | 65   | 81%   |
| yosai/cache/__init__.py              | 0     | 0    | 100%  |
| yosai/cache/abcs.py                  | 48    | 27   | 44%   |
| yosai/cache/cache.py                 | 40    | 21   | 48%   |
| yosai/concurrency/__init__.py        | 0     | 0    | 100%  |
| yosai/concurrency/abcs.py            | 0     | 0    | 100%  |
| yosai/concurrency/concurrency.py     | 18    | 4    | 78%   |
| yosai/concurrency/tbd_concurrency.py | 10    | 10   | 0%    |
| yosai/conf/__init__.py               | 0     | 0    | 100%  |
| yosai/conf/yosaisettings.py          | 51    | 1    | 98%   |
| yosai/context/__init__.py            | 0     | 0    | 100%  |
| yosai/context/context.py             | 54    | 12   | 78%   |
| yosai/event/__init__.py              | 0     | 0    | 100%  |
| yosai/event/abcs.py                  | 15    | 5    | 67%   |
| yosai/event/event.py                 | 78    | 4    | 95%   |
| yosai/exceptions.py                  | 157   | 1    | 99%   |
| yosai/init_yosai.py                  | 5     | 5    | 0%    |
| yosai/logging/__init__.py            | 0     | 0    | 100%  |
| yosai/logging/s_logging.py           | 77    | 56   | 27%   |
| yosai/logging/test_logging.py        | 15    | 15   | 0%    |
| yosai/mgt/__init__.py                | 0     | 0    | 100%  |
| yosai/mgt/abcs.py                    | 20    | 8    | 60%   |
| yosai/mgt/mgt.py                     | 351   | 8    | 98%   |
| yosai/mgt/mgt_settings.py            | 8     | 1    | 88%   |
| yosai/realm/__init__.py              | 0     | 0    | 100%  |
| yosai/realm/abcs.py                  | 91    | 31   | 66%   |
| yosai/realm/realm.py                 | 153   | 9    | 94%   |
| yosai/security_utils.py              | 20    | 5    | 75%   |
| yosai/serialize/__init__.py          | 0     | 0    | 100%  |
| yosai/serialize/abcs.py              | 23    | 4    | 83%   |
| yosai/serialize/serialize.py         | 89    | 56   | 37%   |
| yosai/session/__init__.py            | 0     | 0    | 100%  |
| yosai/session/abcs.py                | 146   | 54   | 63%   |
| yosai/session/session.py             | 792   | 67   | 92%   |
| yosai/session/session_gen.py         | 10    | 0    | 100%  |
| yosai/session/session_settings.py    | 18    | 1    | 94%   |
| yosai/session/session_untested.py    | 1     | 1    | 0%    |
| yosai/subject/__init__.py            | 0     | 0    | 100%  |
| yosai/subject/abcs.py                | 163   | 63   | 61%   |
| yosai/subject/identifier.py          | 67    | 2    | 97%   |
| yosai/subject/subject.py             | 423   | 29   | 93%   |
| yosai/utils/__init__.py              | 0     | 0    | 100%  |
| yosai/utils/utils.py                 | 53    | 37   | 30%   |
|--------------------------------------|-------|------|-------|
| TOTAL                                | 3912  | 682  | 83%   |



GROUP COMMUNICATION
-----------------------------------------------------------------------
Google Groups Mailing List:  https://groups.google.com/d/forum/yosai
Freenode IRC:  #yosai


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
