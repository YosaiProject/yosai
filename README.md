<h1 align=center>🏯 Yosai</h1>
<h2 align=center>Application Security Management for Python</h2>

![alt text](http://i.imgur.com/QDhDfKN.jpg "Yosai 🏯 ")

Yosai is a security management framework.  It is a pythonic port of Apache Shiro: a powerful security management framework written in Java.

Yosai offers developers separation of concern between security management and other aspects of any complicated system built today.  An intuitive user-developer API allows Yosai to be integrated with a system within minutes.  Yosai is a framework with well-defined interfaces between components and so it can be easily extended.

Authentication, Authorization, and Session Management that can support whatever you are looking for:

Does your system require a complicated authorization policy? Yosai supports whatever method of access control that you'll need for your system, from DAC to RBAC.

Looking for two-factor authentication?  Yosai supports X-factor authentication.

[ ![Build Status] [travis-image] ] [travis]
[ ![Release] [release-image] ] [releases]


PROJECT OVERVIEW
-----------------------------------------------------------------------
Please, first familiarize yourself with [Apache Shiro](http://shiro.apache.org/).  It is a remarkable system.

Today, no such open-sourced security framework like Shiro exists for the Python community.  There's an unmet need for one.  Shiro has been battle tested and continues to evolve.  Let's learn from history by porting the java source.  Then, we'll refactor the source using techniques and libraries available in Python and with the expertise from this great development community.

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

|Name                               |Stmts|Miss | Cover|
|-----------------------------------|-----|-----|------|
| yosai/__init__                    | 21  | 0   | 100% |
| yosai/account/__init__            | 0   | 0   | 100% |
| yosai/account/abcs                | 19  | 5   | 74%  |
| yosai/authc/__init__              | 5   | 0   | 100% |
| yosai/authc/abcs                  | 64  | 21  | 67%  |
| yosai/authc/authc                 | 153 | 11  | 93%  |
| yosai/authc/authc_account         | 55  | 7   | 87%  |
| yosai/authc/context               | 38  | 2   | 95%  |
| yosai/authc/credential            | 50  | 5   | 90%  |
| yosai/authc/strategy              | 100 | 6   | 94%  |
| yosai/authz/__init__              | 1   | 0   | 100% |
| yosai/authz/abcs                  | 47  | 16  | 66%  |
| yosai/authz/authz                 | 262 | 16  | 94%  |
| yosai/cache/__init__              | 0   | 0   | 100% |
| yosai/cache/abcs                  | 48  | 27  | 44%  |
| yosai/cache/cache                 | 37  | 37  | 0%   |
| yosai/concurrency/__init__        | 1   | 0   | 100% |
| yosai/concurrency/concurrency     | 16  | 4   | 75%  |
| yosai/concurrency/tbd_concurrency | 10  | 10  | 0%   |
| yosai/conf/__init__               | 1   | 0   | 100% |
| yosai/conf/yosaisettings          | 51  | 1   | 98%  |
| yosai/context/__init__            | 1   | 0   | 100% |
| yosai/context/context             | 40  | 10  | 75%  |
| yosai/event/__init__              | 1   | 0   | 100% |
| yosai/event/abcs                  | 15  | 5   | 67%  |
| yosai/event/event                 | 79  | 4   | 95%  |
| yosai/exceptions                  | 147 | 1   | 99%  |
| yosai/init_yosai                  | 5   | 5   | 0%   |
| yosai/logging/__init__            | 1   | 0   | 100% |
| yosai/logging/s_logging           | 77  | 56  | 27%  |
| yosai/logging/test_logging        | 15  | 15  | 0%   |
| yosai/realm/__init__              | 1   | 0   | 100% |
| yosai/realm/abcs                  | 42  | 12  | 71%  |
| yosai/realm/realm                 | 88  | 3   | 97%  |
| yosai/security/__init__           | 0   | 0   | 100% |
| yosai/security/abcs               | 22  | 22  | 0%   |
| yosai/security/security           | 463 | 463 | 0%   |
| yosai/serialize/__init__          | 1   | 0   | 100% |
| yosai/serialize/abcs              | 18  | 3   | 83%  |
| yosai/serialize/serialize         | 34  | 2   | 94%  |
| yosai/session/__init__            | 3   | 0   | 100% |
| yosai/session/abcs                | 142 | 54  | 62%  |
| yosai/session/session             | 782 | 78  | 90%  |
| yosai/session/session_gen         | 10  | 0   | 100% |
| yosai/session/session_settings    | 18  | 1   | 94%  |
| yosai/session/session_untested    | 1   | 1   | 0%   |
| yosai/subject/__init__            | 0   | 0   | 100% |
| yosai/subject/abcs                | 208 | 208 | 0%   |
| yosai/subject/principal           | 85  | 85  | 0%   |
| yosai/subject/subject             | 456 | 456 | 0%   |
| yosai/utils/__init__              | 1   | 0   | 100% |
| yosai/utils/utils                 | 53  | 19  | 64%  |
|-----------------------------------|-----|-----|------|
|TOTAL                              |3605 | 934 | 74%  |


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

