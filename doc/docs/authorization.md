# Authorization

![authz](img/authorization.png)

Authorization, also known as Access Control, is concerned with the rules and
mechanisms governing how someone or something accesses resources (in this context, within a software application). Informally speaking, authorization is concerned with “who can do what”.


## Role-Based Access Control

There are many access control models [in use today](https://en.wikipedia.org/wiki/Access_control).  By default, Yosai enforces access control by evaluating roles and permissions assigned to a user.
These roles and permissions are derived from a Role-Based Access Control (RBAC) model. Note that although a default support for RBAC is provided, your Realm implementation ultimately decides how your permissions and roles are grouped together and whether to return a “yes” or a “no” answer to Yosai.  This feature
allows you to architect your application in the manner you chose.

[For more information about RBAC](http://csrc.nist.gov/groups/SNS/rbac/)

``yosai.core`` obtains roles and permissions from a repository, such as a
relational database.  Designing and implementing the RBAC data model and its
authorization policy it represents are concerns beyond the scope
of yosai.core. As mentioned earlier, Yosai can support any data model for
access control and doesn’t force one on you.  However, a basic, flat RBAC
model was implemented for Yosai, [as an extension](https://github.com/YosaiProject/yosai_alchemystore), so to facilitate other extension projects.


## Key Concepts

The key concepts to understand about authorization in Yosai involve these relationships:

![user_role_permission](img/user_role_permission.png)

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


## Access Control Levels and Styles

Two "levels" of access control are available:  **role-level** and **permission-level**.

Yosai supports "explicit" role-level access control.  With explicit role-level
access control, a developer specifies the role names that are required to gain
access to an operation.

Permission-level access control is considered superior to role level.
With it, a developer can model authorization requirements ranging from the most
summary to the most detailed.

Both levels of access control can be performed using two styles:

- The **declarative style** of authorization involves use of a decorator that performs one of the two levels of access control.  The wrapped method is never called if authorization fails.

- The **imperative style** of authorization involves in-line access control within the operation that requires authorization.


### Levels and Styles Illustrated

Following is an example of what role-level authorization looks like when using
either style of access control.  In this example, we only allow a user to
delete a comment from a message board (subreddit) if the user is a moderator or
admin.  In other words, the user is a member of *either* the moderator or admin
roles.  In reality, we would layer additional access control to the
remove_comment method so that the creator of the post may also delete the
comment, but this detail is left out for simplicity's sake and only to
highlight role-level access control.

### Native vs Web Yosai APIs

In the examples below, you will see use of the Yosai API, such as ```@Yosai.requires_role```.
You use the ``Yosai`` API to secure non-web applications.  When you are working
with web applications, use the ``WebYosai`` API instead.

### Declarative Style

```Python

@Yosai.requires_role(roleid_s=['moderator', 'admin'], logical_operator=any)
def remove_comment(self, submission):
   self.database_handler.delete(submission)
```

### Imperative Style

Note that the following example assumes that a ``yosai`` instance has already
been instantiated and configured with a SecurityManager.  See the ``yosai init``
documentation for how to do that.
```Python
def remove_comment(self, yosai, submission):
    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()

        try:
            subject.check_role(['moderator', 'creator'], logical_operator=any)
        except UnauthorizedException:
            print('Cannot remove comment:  Access Denied.'')

        self.database_handler.delete(submission)
```

!!! note ""
    Role-level access control is inferior to permission-level access control, but since it has its niche use, is available in Yosai.  It is highly recommended that you choose permission-level access control policies for your application.

# Permissions

A permission states what behavior can be performed in an application but not who
can perform them. Permissions are modeled in Yosai using a flexible design that
allows a developer to choose an appropriate level of detail that suits the
authorization policy governing a software application.

A Permission can be represented in Yosai as a `formatted string` or as a
`Permission` object.  First, let's consider the formatted string.

## 1. String-formatted Permission

The following string presents a permission formatted using a syntax recognized
by Yosai.  Please do not pay attention to the actual labels used but rather the format: `'section1:section2item1,section2item2:section3'`

This Permission string is composed of delimited sections, one that you should notice that includes delimited sub-sections.  As you can see, the default *section delimiter* is the **colon**, and the sub-section delimiter is a **comma**.

A developer can control what the sections (or 'parts') of a permission represent. However, a default implementation of a Permission is provided in Yosai and it is formatted as follows: `'domain:action:instance'`


## 2. Permission object instance

A `DefaultPermission` is expressed in Yosai as a *combination* of resource type (domain), the action(s) that is acted upon that resource type, and instance(s) of that resource type. This three-section format suits many permission modeling requirements. However, should a developer have more complicated requirements, Permissions can be modeled in even more complicated manner.  For example, suppose you wish to set boundaries on a permission by contextualizing when a permission is granted. A permission can be bound to a particular context, also known as 'scoping', granting permission to perform an operation only under certain circumstances: `'context:domain:action:target'`

## Permission Modeling

Following are a few examples of what a Permission string looks like.  We'll base these examples on Reddit [moderator permissioning](https://www.reddit.com/wiki/moderation), with liberties taken to their modeling so as to make it relevant for these examples.  If you are unfamiliar with the role of moderator, please [visit this site](https://www.reddit.com/r/modnews/related/18wmu5/new_feature_moderator_permissions/).

Moderators have management oversight of 'subreddit' message forums.
Their responsibilities provide them with controls to manage submissions and
comments (collectively, "items").  We'll use a few of these controls for
our examples:

### Permission:  "remove items"

This seems straightforward, right?  A moderator can remove submissions and
comments.  Let's consider how item-removal permissioning may be modeled.

One way to model this is by using two permissions, each defining an operation
on a type of resource:
```bash
1) 'submission:remove'
2) 'comment:remove'
```

A moderator will either be assigned to a single role that includes both of these permissions or assigned to two roles where each role includes one of the above permissions.

Note that if a moderator were to be assigned the above permissions that
the user would have moderator status across **all** of reddit.  Such power is too great and is hopefully beyond the grasp of any one individual in the production environment.  With this given, it is more likely that permission is *scoped* such that item removal is limited to a particular subreddit:

```bash
1) 'subreddit_id123:submission:remove'
2) 'subreddit_id123:comment:remove'
```

With these permissions, a user is *authorized* to remove items within
the subreddit that the user is assigned a moderator role.

### Permission:  "categorize items as NSFW"

This permission marks items as not suitable for work environments. Let's add this new activity to the prior permission:

```bash
1) 'subreddit_id123:submission:remove, categorize_nsfw'
2) 'subreddit_id123:comment:remove, categorize_nsfw'
```


Thus far, we've defined two permissions that allow the removal of and
labeling of nsfw of submission and comment resource types.

Suppose that you're a developer working for Reddit.  You receive a request to create a process for moderators to remove a message post, consisting of the submission AND the comments supporting it.  One of your team members uses the permission modeling above to provide you with a specification of the authorization that is required to remove a post:

To remove a post, a user must have BOTH permissions:
```bash
1) 'subreddit_id123:submission:remove, categorize_nsfw'
2) 'subreddit_id123:comment:remove, categorize_nsfw'
```

## You Implement Your Authorization Policy, Yosai enforces it

Access control begins with an authorization policy.  A user is granted permissions through an authorization policy.  The policy states how a user is granted permission to perform an action on a type of resource, perhaps a specific resource instance, and potentially bounded by a particular context. A data model supporting the authorization policy is queried to obtain authorization information -- permissions and/or roles. The authorization policy, its data model, and the administrative system that manages the policy is decided by an organization and is outside the scope of Yosai's value proposition: Yosai enforces an authorization policy but does not provide one. Yosai obtains a user's permissions (or roles) from an outside source and then interprets them to determine whether a user is authorized.


## Authorization Events

An Event is emitted to the singleton EventBus when the results of authorization are obtained.  The results are comprehensive:  every permission or role that is checked is included along with a Boolean indicating whether authorization was granted for it.  A summary "granted" or "denied" event is also communicated when a Boolean check-authorization is submitted to Yosai. If you would like to learn more about Event processing, please refer to the documentation about EventProcessing [here](http://yosaiproject.github.io/yosai/events/).

Events are communicated using a publish-subscribe paradigm.  In the case of
Authorization, the `ModularRealmAuthorizer` publishes an event to a channel (an
internal Event Bus). The EventBus relays an event to consumers who have
subscribed to the event's topic. It relays the event by calling the callback
method registered for a consumer, using the event payload as its argument(s).

The following table lists the Authorization-related events and subscriber(s):

| Event Topic              | Subscriber(s)
|--------------------------|---------------
| AUTHORIZATION.GRANTED    | EL            
| AUTHORIZATION.DENIED     | EL            
| AUTHORIZATION.RESULTS    | EL            

EL = `yosai.core.event.event.EventLogger`


# Authorization API Reference

Yosai provides role-level and permission-level access control.

Both levels of access control can be performed using two styles:

- The **Declarative Style** of authorization involves use of a decorator that performs one of the two levels of access control (role or permission).  The wrapped method is never called if authorization fails.

- The **Imperative Style** of authorization involves in-line access control within the operation that requires authorization.


## Declarative-Style Authorization

Declarative-style authorization allows you to itemize access requirements for a function call.  There are two declarative-style "authorizers", one for permission-level and another for role-level access control.  An ``AuthorizationException`` is raised when a user fails to meet specified access requirements. Following is the API you may use for declarative-style

```Python
    # Permission-level
    def requires_permission(permission_s, logical_operator=all):
        """
        Requires that the calling Subject be authorized to the extent that is
        required to satisfy the permission_s specified and the logical operation
        upon them.

        :param permission_s:   the permission(s) required
        :type permission_s:  a List of Strings or List of Permission instances

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (any, all)
        :type: any OR all (from python standard library)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          permission
        """
        pass


    def requires_dynamic_permission(permission_s, logical_operator=all):
        """
        This method requires that the calling Subject be authorized to the extent
        that is required to satisfy the dynamic permission_s specified and the logical
        operation upon them.  Unlike ``requires_permission``, which uses statically
        defined permissions, this function derives a permission from arguments
        specified at declaration.

        Dynamic permissioning requires that the dynamic arguments be keyword
        arguments of the decorated method.

        :param permission_s:   the permission(s) required
        :type permission_s:  a List of Strings or List of Permission instances

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          permission
        """
        pass

    # Role-level
    def requires_role(roleid_s, logical_operator=all):
        """
        Requires that the calling Subject be authorized to the extent that is
        required to satisfy the roleid_s specified and the logical operation
        upon them.

        :param roleid_s:   a collection of the role(s) required, specified by
                           identifiers (such as a role name)
        :type roleid_s:  a List of Strings

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (any, all)
        :type: any OR all (from python standard library)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          role membership
        """
        pass
```

``logical_operator``, the second parameter of both declarative-style authorizers, can be either ``any`` or ``all`` functions from the python standard library.  Use ``any`` when you want to evaluate each item *independently* of the others and ``all`` when you want to evaluate items *collectively*.


### Example 1:  All Permissions are Required

The following permissions are required, collectively, to call this_function.
When this_function is called, the caller of this_function should be ready to handle an AuthorizationException if the user is denied access:
```Python
    @Yosai.requires_permission(['domain1:action1', 'domain2:action2'], all)
    def this_function(...):
        ...
```

### Example 2:  Any Permission Specified is Acceptable

The following permissions are required, each independently satisfying the access control requirement, to call this_function. When this_function is called, the caller should be ready to handle an AuthorizationException if the user is denied access:
```Python
    @Yosai.requires_permission(['domain1:action1', 'domain2:action2'], any)
    def this_function(...):
        ...
```

### Example 3:  All Roles are Required

The following roles are required, collectively, to call this_function.
When this_function is called, the caller of this_function should be ready to handle an AuthorizationException if the user is denied access:
```Python
    @Yosai.requires_role(['role1', 'role2'], all)
    def this_function(...):
        ...
```

### Example 4:  Any Role Specified is Acceptable

The following roles are required, each independently satisfying the access control requirement, to call this_function. When this_function is called, the caller should be ready to handle an AuthorizationException if the user is denied access:
```Python
@Yosai.requires_role(['role1', 'role2'], any)
def this_function(...):
    ...
```


### Example 5:  Any Permission, Specified Dynamically, is Acceptable

The following permissions are required, each independently satisfying the access control requirement, to call this_function.  Notice how arguments are obtaining dynamically.  If you decide to use dynamic-argument permissions, you reference the arguments using string-formatting syntax.
Dynamic arguments must be passed as keyword arguments to the decorated function.  In
this example, this_function must be called like this_function(kwarg1=..., kwarg2=...)

When this_function is called, the caller should be ready to handle an AuthorizationException if the user is denied access:
```Python
    @Yosai.requires_dynamic_permission(['{kwarg1.domain}:action1',
                                  '{kwarg2.domain}:action2'], any)
    def this_function(...):
        ...
```

## Imperative-Style Authorization

Imperative-Style authorization is used when you want to control access from within your source code, step by step, with more control over the process of checking access and responding to authorization results.  It is the more "granular" of the two styles.

Following is the API you may use for imperative-style authorization:

```Python
# Permission-level methods:
# -------------------------------------------------
    def is_permitted(permission_s):
        """
        Determines whether any Permission(s) associated with the subject
        implies the requested Permission(s) provided.

        :param permission_s: a collection of 1..N permissions, all of the same type
        :type permission_s: List of Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the authz_abcs.Permission and a
                  Boolean indicating whether the permission is granted
        """
        pass

    def is_permitted_collective(permission_s, logical_operator):
        """
        This method determines whether the requested Permission(s) are
        collectively granted authorization.  The Permission(s) associated with
        the subject are evaluated to determine whether authorization is implied
        for each Permission requested.  Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        If operator=ANY: returns True if any requested permission is implied permission
        If operator=ALL: returns True if all requested permissions are implied permission
        Else returns False

        :param permission_s:  a List of authz_abcs.Permission objects

        :param logical_operator:  indicates whether *all* or at least one
                                  permission check is true, *any*
        :type: any OR all (functions from python stdlib)

        :returns: a Boolean
        """
        pass

    def check_permission(permission_s, logical_operator):
        """
        This method determines whether the requested Permission(s) are
        collectively granted authorization.  The Permission(s) associated with
        the subject are evaluated to determine whether authorization is implied
        for each Permission requested.  Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        This method is similar to `is_permitted_collective` except that it
        raises an AuthorizationException if collectively False else does not
        return any value.

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of authz_abcs.Permission objects or Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python stdlib)

        :raises UnauthorizedException: if any permission is unauthorized
        """


# Role-level methods:
# -------------------------------------------------
    def has_role(roleid_s):
        """
        Determines whether a Subject is a member of the Role(s) requested

        :param roleid_s: 1..N role identifiers (strings)
        :type roleid_s:  Set of Strings

        :returns: a frozenset of tuple(s), each containing the Role identifier
                  requested and a Boolean indicating whether the subject is
                  a member of that Role
                  - the tuple format is: (roleid, Boolean)
        """
        pass

    def has_role_collective(roleid_s, logical_operator):
        """
        This method determines whether the Subject's role membership
        collectively grants authorization for the roles requested.  The
        Role(s) associated with the subject are evaluated to determine
        whether the roles requested are sufficiently addressed by those that
        the Subject is a member of. Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        If operator=ANY, returns True if any requested role membership is
                         satisfied
        If operator=ALL: returns True if all of the requested permissions are
                         implied permission
        Else returns False

        :param roleid_s: 1..N role identifiers (strings)
        :type roleid_s:  Set of Strings

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :rtype:  bool
        """
        pass

    def check_role(role_ids, logical_operator):
        """
        This method determines whether the Subject's role membership
        collectively grants authorization for the roles requested.  The
        Role(s) associated with the subject are evaluated to determine
        whether the roles requested are sufficiently addressed by those that
        the Subject is a member of. Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        This method is similar to has_role_collective except that it raises
        an AuthorizationException if collectively False else does not return any

        :param roleid_s: 1..N role identifiers (strings)
        :type roleid_s:  Set of Strings

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          role membership
        """
        pass

```

The first argument of every method is a List containing *either* authorization object instances (`Permission` or `Role`) *or* String(s). Yosai does *not* support a commingling of the two supported types.


You will notice that some of the methods in the imperative-style authorization API include a second parameter, ``logical_operator``.  This parameter can be one of two values: either ``any`` or ``all`` functions from the python standard library.  Use ``any`` when you want to evaluate each item *independently* of the others and ``all`` when you want to evaluate items *collectively*.

Note that the following set of examples assumes that a ``yosai`` instance has already
been instantiated and configured with a SecurityManager.  See the ``yosai init``
documentation for how to do that:

### Example 1:  is_permitted
```Python
    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()
        results = subject.is_permitted(['domain1:action1', 'domain2:action2'])

        if any(is_permitted for permission, is_permitted in results):
            print('any permission is granted')

        if all(is_permitted for permission, is_permitted in results):
            print('all permission is granted, too!')

```
!!! note ""
    `results` is a list of tuples, each containing a Permission object and a Boolean value indicating whether access is granted (True) or denied (False)


### Example 2:  is_permitted_collective
```Python
    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()
        any_result_check = subject.is_permitted_collective(['domain1:action1',
                                                                 'domain2:action2'], any)
        if any_result_check:
            print('any permission is granted')

        all_result_check = subject.is_permitted_collective(['domain1:action1',
                                                                 'domain2:action2'], all)

        if all_result_check:
            print('all permission is granted, too!')
```
!!! note ""
    `any_result_check` and `all_result_check` are Boolean values


### Example 3:  check_permission
```Python
    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()
        try:
            subject.check_permission(['domain1:action1',
                                           'domain2:action2'],
                                          any)
        except AuthorizationException:
            print('any permission denied')
        else:
            print('any permission granted')

        try:
            subject.check_permission(['domain1:action1',
                                           'domain2:action2'],
                                          all)
        except AuthorizationException:
            print('all permission denied')
        else:
            print('all permission granted')
```
!!! note ""
    `check_permission` succeeds quietly else raises an AuthorizationException


### Example 1:  has_role
```Python
    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()
        results = subject.has_role(['role1', 'role2'])

        if any(has_role for role, has_role in results):
            print('any role is confirmed')

        if all(has_role for role, has_role in results):
            print('all role is confirmed, too!')

```
!!! note ""
    `results` is a list of tuples, each containing a Role and a Boolean value indicating whether role membership is confirmed (True if so)


### Example 2:  has_role_collective
```Python
    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()
        any_result_check = subject.has_role_collective(['role1', 'role2'], any)

        if any_result_check:
            print('any role is confirmed')

        all_result_check = subject.has_role_collective(['role1', 'role2'], all)

        if all_result_check:
            print('all role is confirmed, too!')
```
!!! note ""
    `any_result_check` and `all_result_check` are Boolean values


### Example 3:  check_role
```Python
    with Yosai.context(yosai):
        subject = Yosai.get_current_subject()
        try:
            subject.check_role(['role1', 'role2'], any)

        except AuthorizationException:
            print('any role denied')
        else:
            print('any role confirmed')

        try:
            subject.check_role(['role1', 'role2'], all)

        except AuthorizationException:
            print('all role denied')
        else:
            print('all role confirmed')
```
!!! note ""
    `check_role` succeeds quietly else raises an AuthorizationException


## References
[OWASP Access Control Cheat Sheet]( https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)
