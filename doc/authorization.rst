Authorization, also known as Access Control, is concerned with the rules and
mechanisms governing how users access resources in an application. Informally
speaking, authorization is concerned with “who can do what”.

The key concepts to understand about Authorization in Yosai involve this relationship:

Permissions are *associated with* roles. Users are *assigned to* roles.
[image of user, role, and permission]


A **Permission** specifies an action performed in the system on a resource.

A **role** is a group of permissions. Organizations are known to group permissions
by task or various job functions. Roles can be granted new permissions as new
applications and systems are incorporated, and permissions can be revoked from
roles as needed.


A **user** refers to a person who interfaces with the software application.
A user is provided a user account that allows an application to uniquely
identify it.  User accounts are often identified by a Username/UserID
attribute or email address.  Users are assigned roles based on the user's
responsibilities and qualifications. Users can be easily reassigned from one role
to another.


Permissions
===========
A permission states what behavior can be performed in an application but not who
can perform them. Permissions are modeled in Yosai using a flexible design that
allows a developer to choose an appropriate level of detail that suits the
authorization policy governing a software application.

A Permission can be represented in Yosai as a ``formatted string`` or as a ``Permission``
 object.  First, let's consider the formatted string.

The Permission string is composed of delimited sections that *may* consist of
delimited sub-sections.  The default *section delimiter* is the colon, ':', and
the sub-section delimiter is a comma ','. Here are a few examples of what
a Permission string looks like.  We'll base these examples on Reddit moderator
permissioning[1]:




ResourceType:Operation:ResourceInstance

A 'Permission' is expressed in Yosai as a *combination* of resource type, the
operation(s) that is acted upon that resource type, and instance(s) of that
resource type. Further, a permission may be bound to a particular context,
also known as 'scoping', granting permission to perform an operation only under
certain circumstances.



Domain (or 'Resource Type')
---------------------------


Object (or 'Resource')
-----------------------
An object can be any resource *instance* accessible by a computer system, such as
business objects, files, or even peripherals such as printers.

Operation (or 'Action')
-----------------------
An operation is an action invoked by a subject.



You Implement Your Authorization Policy, Yosai enforces it
----------------------------------------------------------
Access control begins with an authorization policy.  A user is granted permissions
through an authorization policy.  The policy states how a user is granted
permission to perform an action on a type of resource, perhaps a specific resource
instance, and potentially bounded by a particular context. A data model supporting
the authorization policy is queried to obtain authorization information --
permissions and/or roles. The authorization policy, its data model, and the
administrative system that manages the policy is decided by an organization and
is outside the scope of Yosai's value proposition: Yosai enforces an authorization
policy but does not provide one. Yosai obtains a user's permissions (or roles)
from an outside source and then interprets them to determine whether a user is authorized.

[1] Reddit Moderator Permissioning: https://www.reddit.com/r/modnews/related/18wmu5/new_feature_moderator_permissions/
