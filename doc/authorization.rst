Authorization
=============
Authorization, also known as Access Control, is concerned with the rules and
mechanisms governing the ways that users access resources in an application ,
or informally speaking, is concerned with “who can do what”.

A standard terminology has developed over the last 30 years that is used to
describe access control specifications such as those that follow:
    A user is granted permission to perform an action on a type of resource,
    perhaps a specific resource instance, potentially bounded by a particular
    context.

User
----
'User' refers to a person who interfaces with the software application.
A user is provided a user account that allows an application to uniquely
identify it.  User accounts are often identified by a Username/UserID
attribute or email address.

Subject
-------
As mentioned in the introduction, every security related operation is performed
in the context of a **Subject**.  The term "Subject" is generally synonymous with
"User" except that aside from human beings also includes non-human, system entities.
  In other words, a **Subject** is a *person* or a *thing*.

Permission
----------
Permissions are authorizations to perform some action in the system.  A user
is granted its permissions through an Authorization Policy.  A data model
representing the authorization policy is analyzed (queried) to obtain a user's
permissions.  Yosai does not manage an authorization policy but rather an enforcer
of the policy.  Yosai obtains a user's Permissions from an outside source and then
analyzes them to determine whether a user is authorized.

Permissions have a flexible design in Yosai, providing lattitude to
developers to decide how a Permission is modeled.  Be that as it may, a default
Permission syntax and implementation of it is provided in yosai.core.

A user is assigned permission: a permission states what behavior can be performed
 in an application but not who can perform them.

A 'Permission' is expressed in Yosai as a *combination* of
resource type, the operation(s) that is acted upon that resource type, and
instance(s) of that resource type. Further, a permission may be bound to a
particular context, also known as 'scoping', granting permission to perform an
operation only under certain circumstances.


Suppose, for instance, that a hospital's prescription compliance system states
that a nurse may be able to fill a patient's prescription, for a specific type of
 medication approved by a physician, if the nurse has been assigned responsibility
 for that patient and if the prescription fill request is submitted to a pharmacy
 during the nurse's shift.

 There are multiple ways to model permissions such as this.  In this example,
 such permissions may be modeled as:

   context key = (nurse_shift_id, patient_id_123)
   domain = prescription
   operation = fill
   object = prescription_id_abc123


Domain (or 'Resource Type')
---------------------------


Object (or 'Resource')
-----------------------
An object can be any resource *instance* accessible by a computer system, such as
business objects, files, or even peripherals such as printers.

Operation (or 'Action')
-----------------------
An operation is an action invoked by a subject.
