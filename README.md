<h1 align=center>Yosai</h1>

![alt text](http://i.imgur.com/QDhDfKN.jpg "🏯 Yosai")

Yosai is a pythonic port of Apache Shiro-- a powerful security management framework written in Java.  

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
In Japanese, the word Shiro translates to "Castle".  Yosai translates to "Fortress".  Like the words, the security platforms are similiar in meaning yet not the same.



PROJECT STATUS
-----------------------------------------------------------------------
I am a one man army who is eager to share the love for this open source project.   Well-seasoned 
Python developers who understand best practices in python design and software architecture are urged to consider joining this Project.  I am nearly finished with the rough-rough-rough port to python, leaving much of the source 
intact but have been addressing the exceptionally-java-based solutions as I come across them.  I expect to release this v0.01 baseline to the repository within the next two weeks.

05/20/2015:  Testing is well under way.  Unit testing (aka isolated testing) for /authc is nearly complete.
            
CONTACT INFORMATION
-----------------------------------------------------------------------
If you would like to get involved, please contact me by the email address in my github profile.  I am often
available on FreeNode IRC channels #python and #pyramid under the nickname dowwie.

             
APACHE SHIRO VERSION USED
-----------------------------------------------------------------------
Yosai vX.X.X is as of Apache Shiro 2.0 Alpha, Revision xxxxxx      
