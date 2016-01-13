What is Authorization?
======================
Authorization, also known as Access Control, is concerned with the rules and
mechanisms governing how someone or something accesses resources (in this context, 
within a software application). Informally speaking, authorization is concerned with 
“who can do what”.

The objective of this documentation is to introduce the core concepts
of Authorization in Yosai.  Please consult the API Reference if you wish to see
the authorization API in its entirety.


Role-Based Access Control
-------------------------
There are many access control models in use today [1].  Yosai enforces access 
control by evaluating roles and permissions assigned to a user.  These roles 
and permissions are derived from a Role-Based Access Control (RBAC) model.

For more information about RBAC: http://csrc.nist.gov/groups/SNS/rbac/ 

yosai.core obtains roles and permissions from a repository, such as a 
relational database.  Designing and implementing the RBAC data model and the
authorization policy it represents are concerns beyond the scope
of yosai.core.  However, a basic, flat RBAC model was implemented for yosai 
as an extension so to facilitate other extension projects [2].


How is Authorization conducted in Yosai?
========================================

The key concepts to understand about authorization in Yosai involve these relationships:

[image of user, role, and permission]

Permissions are *associated with* roles. Users are *assigned to* roles.

A **Permission** specifies an action performed in the system on a resource.

A **Role** is a group of permissions. Organizations are known to group permissions
by task or various job functions. Roles can be granted new permissions as new
applications and systems are incorporated, and permissions can be revoked from
roles as needed.

A **User** refers to a person who interfaces with the software application.
A user is provided a user account that allows an application to uniquely
identify it.  User accounts are often identified by a Username/UserID
attribute or email address.  Users are assigned roles based on the user's
responsibilities and qualifications. Users can be easily reassigned from one role
to another.

Yosai obtains a user's authorization information (assigned permissions
and role memberships) and then determines whether the user meets
the access required to perform an operation in an application.


Access Control Levels and Styles
--------------------------------------------
Two "levels" of access control are available:  **role-level** and **permission-level**.

Yosai supports "explicit" role-level access control.  With explicit role-level
access control, a developer specifies the role names that are required to gain
access to an operation.

Permission-level access control is considered superior to role level.
With it, a developer can model authorization requirements ranging from the most
summary to the most detailed.

Both levels of access control can be performed using two styles:
- The **declarative style** of authorization involves use of a decorator that performs
one of the two levels of access control.  The wrapped method is never called
if authorization fails.

- The **imperative style** of authorization involves in-line access control within
the operation that requires authorization.


Levels and Styles Illustrated
-----------------------------
Following is an example of what role-level authorization looks like when using 
either style of access control.  In this example, we only allow a user to
delete a comment from a message board (subreddit) if the user is a moderator or
admin.  In other words, the user is a member of *either* the moderator or admin
roles.  In reality, we would layer additional access control to the
remove_comment method so that the creator of the post may also delete the
comment, but this detail is left out for simplicity's sake and only to
highlight role-level access control:

Declarative Style
~~~~~~~~~~~~~~~~~
.. code-block:: python

    @requires_role(roleid_s=['moderator', 'admin'], logical_operator=any)
    def remove_comment(self, submission):
       self.database_handler.delete(submission)

Imperative Style
~~~~~~~~~~~~~~~~
.. code-block:: python

    def remove_comment(self, submission):
        subject = SecurityUtils.get_subject()

        try:
            subject.check_role(['moderator', 'creator'], logical_operator=any)
        except UnauthorizedException:
            print('Cannot remove comment:  Access Denied.'')

        self.database_handler.delete(submission)

.. note::
    Role-level access control is inferior to permission-level access control, but
    since it has its niche use, is available in Yosai.  It is highly recommended that
    you choose permission-level access control policies for your application.

Does the user's assigned permissions imply permission of the permissions required
to proceed.


Permissions
-----------
A permission states what behavior can be performed in an application but not who
can perform them. Permissions are modeled in Yosai using a flexible design that
allows a developer to choose an appropriate level of detail that suits the
authorization policy governing a software application.

A Permission can be represented in Yosai as a ``formatted string`` or as a 
``Permission`` object.  First, let's consider the formatted string.

I) Permission String
--------------------
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


II) Permission object
---------------------

A ``DefaultPermission`` is expressed in Yosai as a *combination* of resource type (domain),
the action(s) that is acted upon that resource type, and instance(s) of that resource type.
This three-section format suits many permission modeling requirements. However, should
a developer have more complicated requirements, Permissions can be modeled in
even more complicated manner.  For example, suppose you wish to set boundaries
on a permission by contextualizing when a permission is granted. A permission can
be bound to a particular context, also known as 'scoping', granting permission to
perform an operation only under certain circumstances:
    ``'context:domain:action:target'``



Authorization Case Study
------------------------

Role Engineering
----------------

Permission Modeling
-------------------
Following are a few examples of what a Permission string looks like.  We'll base these
examples on Reddit moderator permissioning [3], with liberties taken to their
modeling so as to make it relevant for these examples.  If you are unfamiliar
with the role of moderator, please visit this site [4].

Moderators have management oversight of 'subreddit' message forums.
Their responsibilities provide them with controls to manage submissions and
comments (collectively, "items").  We'll use a few of these controls for
our examples:

    I) Permission:  remove items

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

    II) Permission:  mark items "NSFW" -- not suitable for work environments

        Let's add this new activity to the prior permission:

            'subreddit_id123:submission:remove, mark_nsfw'
            'subreddit_id123:comment:remove, mark_nsfw'

    Thus far, we've defined two permissions that allow the removal of and
    labeling of nsfw of submission and comment resource types.

    Suppose that you're a developer working for Reddit.  You receive a request to
    create a process for moderators to remove a message post, consisting of the
    submission AND the comments supporting it.  One of your team members uses
    the permission modeling above to provide you with a specification of the
    authorization that is required to remove a post:

        To remove a post, a user must have BOTH permissions:
            'subreddit_id123:submission:remove, mark_nsfw'
            'subreddit_id123:comment:remove, mark_nsfw'


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

[1] Access Control Models:  https://en.wikipedia.org/wiki/Access_control
[2] YosaiAlchemyStore: https://github.com/YosaiProject/yosai_alchemystore 
[3] Reddit Moderator Overview:  https://www.reddit.com/wiki/moderation
[4] Reddit Moderator Permissioning: https://www.reddit.com/r/modnews/related/18wmu5/new_feature_moderator_permissions/
