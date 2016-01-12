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

The Permission String
---------------------
The following string presents a permission formatted using a syntax recognized
by Yosai.  Please do not pay attention to the actual labels used but rather the format:

    ``'section1:section2item1,section2item2:section3'``

This Permission string is composed of delimited sections, one that you should notice
that includes delimited sub-sections.  As you can see, the default *section delimiter* is the
**colon**, ':', and the sub-section delimiter is a **comma** ','.

A developer can control what the sections (or 'parts') of a permission represent.
However, a default implementation of a Permission is provided in Yosai and it is
formatted as follows:
    ``'domain:action:instance'``

A 'Permission' is expressed in Yosai as a *combination* of resource type (domain),
the action(s) that is acted upon that resource type, and instance(s) of that
resource type.

This three-section format suits many permission modeling requirements. However, should
a developer have more complicated requirements, Permissions can be modeled in
even more complicated manner.  For example, suppose you wish to set boundaries
on a permission by contextualizing when a permission is granted. A permission can
be bound to a particular context, also known as 'scoping', granting permission to
perform an operation only under certain circumstances:
    ``'context:domain:action:target'``

Following are a few examples of what a Permission string looks like.  We'll base these
examples on Reddit moderator permissioning[2], with liberties taken to their
modeling so as to make it relevant for these examples.  If you are unfamiliar
with the role of moderator, please visit this site [1].

Moderators have management oversight of 'subreddit' message forums.
Their responsibilities provide them with controls to manage submissions and
comments (collectively, "items").  We'll use a few of these controls for
our examples:

    I) a moderator may remove items

    This seems straightforward, right?  A moderator can remove submissions and
    comments.  Let's consider how item-removal permissioning may be modeled.

    One way to model this is by using two permissions, each defining an operation
    on a type of resource:
        'submission:remove'
        'comment:remove'


    A moderator will either be assigned to a single role that includes both of these
    permissions or assigned to two roles where each role includes one of the above
    permissions.

    Note that if a moderator were to be assigned the above permissions that
    the user would have moderator status across **all** of reddit.  Such power is too
    great and is hopefully beyond the grasp of any one individual in the production
    environment.  With this given, it is more likely that permission is *scoped*
    such that item removal is limited to a particular subreddit:

        'subreddit_id123:submission:remove'
        'subreddit_id123:comment:remove'

    With these permissions, a user is *authorized* to remove items within
    the subreddit that the user is assigned a moderator role.

    II) mark items "NSFW" -- not suitable for work environments

        Let's add this new activity to the prior permission:

            'subreddit_id123:submission:remove, mark_nsfw'
            'subreddit_id123:comment:remove, mark_nsfw'

    Thus far, we've defined two permissions that allow the removal and mark_nsfw
    of submission and comment resource types.

    Suppose that you're a reddit developer who just received a request to build
    a process to remove a message post, consisting of the submission AND the
    comments supporting it.  Further, you've been provided a specification
    of the authorization that is required to remove a post:

        To remove a post, a user must have BOTH permissions:
            'subreddit_id123:submission:remove, mark_nsfw'
            'subreddit_id123:comment:remove, mark_nsfw'



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

[1] Reddit Moderator Overview:  https://www.reddit.com/wiki/moderation
[2] Reddit Moderator Permissioning: https://www.reddit.com/r/modnews/related/18wmu5/new_feature_moderator_permissions/
