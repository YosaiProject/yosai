"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

from abc import ABCMeta, abstractmethod


class IdentifierCollection(metaclass=ABCMeta):
    """
    A collection of all identifiers associated with a corresponding Subject.
    An *identifier* in this context is an identifying attribute, such as a
    username or user id or social security number or anything else considered
    an 'identifying' attribute for a Subject.

    An IdentifierCollection organizes its internal identifiers based on the
    Realm where they came from when the Subject was first created.  To obtain
    the identifiers(s) for a specific source (realm), see the from_source method.
    You can also see which realms contributed to this collection via the
    source_names property.
    """

    @property
    @abstractmethod
    def primary_identifier(self):
        """
        Returns the primary identifier used application-wide to uniquely identify
        the owning account/Subject.

        The value is usually always a uniquely identifying attribute specific to
        the data source that retrieved the account data.  Some examples:

         - a UUID
         - a long integer value such as a surrogate primary key in a relational database
         - an LDAP UUID or static DN
         - a String username unique across all user accounts

        Multi-Realm Applications
        -------------------------
         In a single-Realm application, typically there is only ever one unique
         principal to retain and that is the value returned from this method.
         However, in a multi-Realm application, where the IdentifierCollection
         might retain identifiers across more than one realm, the value returned
         from this method should be the single identifier that uniquely identifies
         the subject for the entire application.

         That value is of course application specific, but most applications will
         typically choose one of the primary identifiers from one of the Realms.
         Yosai's default implementations of this interface make this assumption
         by usually simply returning the next iterated upon identifier
         obtained from the first consulted/configured Realm during the
         authentication attempt.  This means in a multi-Realm application, Realm
         configuraiton order matters if you want to retain this default heuristic.

         If this heuristic is not sufficient, most Shiro end-users will need to
         implement a custom AuthenticationStrategy.  An AuthenticationStrategy
         has exact control over the IdentifierCollection returned at the end of
         an authentication attempt via the AuthenticationStrategy
         implementation.

         :returns: the primary identifier used to uniquely identify the owning
                   account/Subject
        """
        pass

    @abstractmethod
    def by_type(self, identifier_type):
        """
        this method's value is controversial in nature in Shiro as it obtains
        identifiers by type
        """
        pass

    @abstractmethod
    def from_source(self, realm_name):
        """
        obtain the identifier for a particular source (realm)
        """
        pass

    @property
    @abstractmethod
    def source_names(self):
        """
        obtain a list of sources (realms) that identifiers have been obtained
        from
        """
        pass

    @property
    @abstractmethod
    def is_empty(self):
        """
        confirms whether the identifier collection is empty
        """
        pass

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)


class MutableIdentifierCollection(IdentifierCollection):

    @abstractmethod
    def add(self, source_name, identifier):
        """
        :type identifier: string
        :type source_name:  string
        """
        pass

    @abstractmethod
    def add_collection(self, identifier_collection):
        """
        :type identifier_collection: subject_abcs.IdentifierCollection
        """
        pass

    @abstractmethod
    def clear(self):
        pass


class IdentifierMap(IdentifierCollection):

    @abstractmethod
    def get_realm_identifier(self, realm_name):
        pass

    @abstractmethod
    def set_realm_identifier(self, realm_name, identifier):
        pass

    @abstractmethod
    def set_realm_identifier(self, realm_name, identifier_name, identifier):
        pass

    @abstractmethod
    def get_realm_identifier(self, realm_name, realm_identifier):
        pass

    @abstractmethod
    def remove_realm_identifier(self, realm_name, identifier_name):
        pass


class SubjectContext(metaclass=ABCMeta):
    """
    A SubjectContext is a 'bucket' of data presented to a SecurityManager
    that interprets data used to construct Subject instances.  It is essentially
    a Map of data with a few additional methods for easy retrieval of objects
    commonly used to construct Subject instances.

    The map can contain anything additional that might be needed by the
    SecurityManager or SubjectFactory implementation to construct Subject
    instances.

    Data Resolution
    ----------------
    The SubjectContext interface allows for heuristic resolution of data
    used to construct a subject instance.  That is, if an attribute has not been
    explicitly assigned, the *resolve methods use heuristics to obtain data
    using methods other than direct attribute access.

    For example, if one references the identifiers property and no identifiers
    are returned, perhaps the identifiers exist in a session or another
    attribute in the context.  The resolve_identifiers method will know
    how to resolve the identifiers based on heuristics.  If the *resolve methods
    return None, then the data could not be achieved through heuristics and must
    be considered unavailable in the context.

    The general idea is that the normal direct attribute access can be called to
    determine whether the value was explicitly set.  The *resolve methods are
    used when actually constructing a Subject instance to ensure the most
    specific/accurate data is used.

    USAGE
    --------------
    Most Yosai end-users will never use a SubjectContext instance directly and
    instead will use a SubjectBuilder (which internally uses a SubjectContext)
    to build Subject instances.
    """
    @abstractmethod
    def resolve_security_manager(self):
        """
        Resolves the SecurityManager instance to be used to back the constructed
        Subject instance (typically used to support DelegatingSubject implementations)
        """
        pass

    @abstractmethod
    def resolve_identifiers(self):
        pass

    @abstractmethod
    def resolve_session(self):
        pass

    @abstractmethod
    def resolve_authenticated(self):
        pass

    @abstractmethod
    def resolve_host(self):
        pass

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)



class Subject(metaclass=ABCMeta):
    """
    A Subject represents state and security operations for a *single*
    application user.  These operations include authentication (login/logout),
    authorization (access control), and session access. A subject is Yosai's
    primary mechanism for single-user security functionality.

    Acquiring a Subject
    ----------------------
    To acquire the currently-executing Subject, application developers will
    almost always use Yosai:

        Yosai.get_subject()

    Almost all security operations should be performed with the Subject returned
    from this method.

    Permission methods
    --------------------
    Note that there are many Permission methods in this interface that
    accept a list of either String arguments or authz_abcs.Permission instances.
    The underlying Authorization subsystem implementations will usually simply
    convert these String values to Permission instances and then call the
    corresponding method.  (Yosai's default implementations do String-to-Permission
    conversion.

    remembered attribute:
    ---------------------
    Returns True if this Subject has an identity (it is not anonymous) and
    the identity (aka identifiers}) is remembered from a successful
    authentication during a previous session.

    Although the underlying implementation determines exactly how this
    method functions, most implementations have this method act as the
    logical equivalent to this code:

        - subject.identifiers is not None and subject.authenticated

    Note as indicated by the above code example, if a Subject is remembered,
    it is *NOT* considered authenticated.  A check against authenticated
    is a more strict check than that reflected by this method.  For example,
    a check to see whether a subject can access financial information should
    almost always depend on subject.authenticated rather, than this method,
    to *guarantee* a verified identity.

    Once the subject is authenticated, it is no longer considered only
    remembered because its identity would have been verified during the
    current session.

    Remembered vs Authenticated
    -----------------------------
    Authentication is the process of *proving* a subject is who it claims to
    be.  When a user is only remembered, the remembered identity gives the
    system an idea who that user probably is, but in reality, the system
    has no way of absolutely *guaranteeing* whether the remembered Subject
    represents the user currently using the application.

    So, although many parts of the application can still perform user-specific
    logic based on the remembered identifiers, such as customized views,
    the application should never perform highly-sensitive operations until
    the user has legitimately verified its identity by executing a successful
     authentication attempt.

    We see this paradigm all over the web, and we will use
    <a href="http://www.amazon.com">Amazon.com</a> as an example:

    When you visit Amazon.com and perform a login and ask it to 'remember me',
     Amazon will set a cookie with your identity.  If you don't log out and
    your session expires, but you come back the next day, Amazon still knows
    who you *probably* are and so you see all of your book and movie
    recommendations and similar user-specific features since these are based
    on your (remembered) user id (identifiers).

    However, if you try to do something sensitive, such as access your
    account's billing data, Amazon forces you to perform an actual log-in,
    requiring your username and password.

    Amazon does this because although it assumes your identity from
    'remember me', it recognized that you were not actually authenticated.
    The only way to really guarantee you are who you say you are, and
    therefore allow you access to sensitive account data, is to require you
    to perform an actual successful authentication.  You can check this
    guarantee via the subject.authenticated method and not via this method.
    """

    @property
    @abstractmethod
    def identifiers(self):
        """
        Returns this Subject's application-wide uniquely identifying principal,
        or None if this Subject is anonymous because it doesn't yet have any
        associated account data (for example, if they haven't logged in).

        The term 'principal' is just a fancy security term for any identifying
        attribute(s) of an application user, such as a username, or user id, or
        public key, or anything else you might use in your application to
        identify a user.  Yosai replaces the term 'principal' with 'identifier'
        in recognition of terminology confusion that Shiro faces using 'principal'.

        Uniqueness
        -----------
        Although given names and family names (first/last) are technically
        considered identifiers as well, Yosai expects the object returned from
        this method to be an identifying attribute unique across your entire
        application.

        This implies that attributes like given names and family names are usually
        poor candidates as return values since they are rarely guaranteed to be
        unique.  Items often used for this value:

            - A long-int RDBMS surrogate primary key
            - An application-unique username
            - A UUID
            - An LDAP Unique ID
            - any other similar, suitable, and unique mechanism valuable to your
              application

        Most implementations will simply return identifiers.primary_principal.
        """
        pass

    @property
    @abstractmethod
    def identifiers(self):
        """
        Returns this Subject's principals (identifying attributes) in the form
        of an IdentifierCollection or None if this Subject is anonymous because
        it doesn't yet have any associated account data (for example, if they
        haven't logged in).

        The word 'principals' is nothing more than a fancy security term for
        identifying attributes associated with a Subject, aka, application user.
        For example, user id, a surname (family/last name), given (first) name,
        social security number, nickname, username, etc, are all examples of a
        principal. Yosai replaces the term 'principal' with 'identifier'
        in recognition of terminology confusion that Shiro faces using
        'principal'.
        """
        pass

    @abstractmethod
    def is_permitted(self, permissions):
        """
        Determines whether any Permission(s) associated with the subject
        implies the requested Permission(s) provided.

        :param permission_s: a collection of 1..N permissions, all of the same type
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :returns: a set of tuple(s), each containing the Permission
                  requested and a Boolean indicating whether permission is
                  granted
                  - the tuple format is: (Permission, Boolean)
        """
        pass

    @abstractmethod
    def is_permitted_collective(self, permissions, logical_operator):
        """
        This method determines whether the requested Permission(s) are
        collectively granted authorization.  The Permission(s) associated with
        the subject are evaluated to determine whether authorization is implied
        for each Permission requested.  Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        If operator=ANY: returns True if any requested permission is implied permission
        If operator=ALL: returns True if all requested permissions are implied permission
        Else returns False

        :param permission_s: a collection of 1..N permissions, all of the same type
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :rtype:  bool
        """
        pass

    @abstractmethod
    def check_permission(self, permissions, logical_operator):
        """
        This method determines whether the requested Permission(s) are
        collectively granted authorization.  The Permission(s) associated with
        the subject are evaluated to determine whether authorization is implied
        for each Permission requested.  Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        This method is similar to is_permitted_collective except that it raises
        an AuthorizationException if collectively False else does not return any
        value.

        :param permission_s: a collection of 1..N permissions, all of the same type
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          permission
        """
        pass

    @abstractmethod
    def has_role(self, role_s):
        """
        Determines whether a Subject is a member of the Role(s) requested

        :param role_s: 1..N role identifiers (strings)
        :type role_s:  Set of Strings

        :returns: a set of tuple(s), each containing the Role identifier
                  requested and a Boolean indicating whether the subject is
                  a member of that Role
                  - the tuple format is: (role, Boolean)
        """
        pass

    @abstractmethod
    def has_role_collective(self, role_s, logical_operator):
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

        :param role_s: 1..N role identifiers (strings)
        :type role_s:  Set of Strings

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :rtype:  bool
        """
        pass

    @abstractmethod
    def check_role(self, role_s, logical_operator):
        """
        This method determines whether the Subject's role membership
        collectively grants authorization for the roles requested.  The
        Role(s) associated with the subject are evaluated to determine
        whether the roles requested are sufficiently addressed by those that
        the Subject is a member of. Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        This method is similar to has_role_collective except that it raises
        an AuthorizationException if collectively False else does not return any

        :param role_s: 1..N role identifiers (strings)
        :type role_s:  Set of Strings

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          role membership
        """
        pass

    @abstractmethod
    def login(self, auth_token):
        """
        Performs a login attempt for this Subject/user.

        If unsuccessful, a subclass of AuthenticationException is raised,
        identifying why the attempt failed.

        If successful, the Account data associated with the submitted
        identifiers/credentials will be associated with this Subject and the
        method will return quietly.

        Upon returning quietly, this Subject instance can be considered
        authenticated and its identifiers attribute will be non-None and
        its authenticated property will be True.

        :param authc_token: the token encapsulating the subject's identifiers
                            and credentials to be passed to the Authentication
                            subsystem for verification
        :type authc_token:  authc_abcs.AuthenticationToken

        :raises AuthenticationException: if the authentication attempt fails
        """
        pass

    @abstractmethod
    def get_session(self, create=None):
        """
        Returns the application Session associated with this Subject based on
        the following criteria:
            - If there is already an existing Session associated with this
              Subject, it is returned and the create argument is ignored.
            - If no Session exists and create is True, a new Session is created,
              associated with this Subject and then returned.
            - If no Session exists and create is False, None is returned.

        :returns: the application Session associated with this Subject
        """
        pass

    @abstractmethod
    def logout(self):
        """
        Logs out this Subject and invalidates and/or removes any associated
        entities, such as a Session and authorization data.  After this method
        is called, the Subject is considered 'anonymous' and may continue to be
        used for another log-in, if desired.

        Web Environment Warning
        -------------------------
        Calling this method in web environments will usually remove any
        associated session cookie as part of session invalidation.  Because
        cookies are part of the HTTP header, and headers can only be set before
        the response body (html, image, etc) is sent, this method in web
        environments must be called before *any* content is rendered.

        The typical approach most applications use in this scenario is to redirect
        the user to a different location (e.g. home page) immediately after
        calling this method.  This is an effect of the HTTP protocol itself and
        not a reflection of Yosai's implementation.

        Non-HTTP environments may of course use a logged-out subject for login
        again if desired.
        """
        pass

    @abstractmethod
    def run_as(self, identifiers):
        """
        Allows this subject to 'run as' or 'assume' another identity indefinitely.
        This method can only be called when the Subject instance already has an
        identity (i.e. it is remembered from a previous log-in or it has
        authenticated in its current session).

        Some notes about run_as:

        - You can determine whether a Subject is 'running as' another identity
          by checking the run_as property.
        - If running as another identity, you can determine what the previous
          identity, the identity just prior to running-as, is by calling the
          get_previous_identifiers method.
        - When you want a Subject to stop running as another identity, you can
          return to its previous identity (the identity just prior to running-as)
          by calling the release_run_as method.

        :param identifiers: the identity to 'run as', aka the identity to
                            *assume* indefinitely
        :type identifiers:  subject_abcs.IdentifierCollection
        """
        pass

    @abstractmethod
    def is_run_as(self):
        """
        Returns True if this Subject is 'running as' another identity other than
        its original one or False otherwise (normal Subject state).  See the
        run_as method for more information.

        :returns: True if this Subject is 'running as' another identity other
                  than its original one or False otherwise (normal Subject state)
        :rtype: bool
        """
        pass

    @abstractmethod
    def get_previous_identifiers(self):
        """
        Returns the previous 'pre run as' identity of this Subject before
        assuming the current run_as identity, or None if this Subject is not
        operating under an assumed identity (normal state). See the run_as
        method for more information.

        :returns: the previous 'pre run as' identity of this Subject before
                  assuming the current run_as identity, or None if this Subject
                  is not operating under an assumed identity (normal state)
        """
        pass

    @abstractmethod
    def release_run_as(self):
        """
        This method releases the current 'run as' (assumed) identity and reverts
        to the previous 'pre run as' identity that existed before run_as was called.

        This method returns 'run as' (assumed) identity being released or None
        if this Subject is not operating under an assumed identity.

        :returns: the 'run as' (assumed) identity being released or None if this
                  Subject is not operating under an assumed identity
        """
        pass

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

# moved from /mgt:
class SubjectStore(metaclass=ABCMeta):
    """
    A SubjectStore is responsible for persisting a Subject instance's internal
    state such that the Subject instance can be recreated at a later time if
    necessary.

    Shiro's default SecurityManager implementations typically use a SubjectStore
    in conjunction with a SubjectFactory after the SubjectFactory creates a
    Subject instance, the SubjectStore is used to persist that subject's state
    such that it can be accessed later if necessary.

    Usage
    --------
    Note that this component is used by SecurityManager implementations to
    manage Subject state persistence.  It does *not* make Subject instances
    accessible to the application (e.g. via yosai.subject).
    """
    @abstractmethod
    def save(self, subject):
        """
        Persists the specified Subject's state for later access.  If there is
        a no existing state persisted, this persists it if possible (i.e. a
        create operation).  If there is existing state for the specified
        Subject, this method updates the existing state to reflect the
        current state (i.e. an update operation).

        :param subject: the Subject instance for which its state will be
                        created or updated
        :returns: the Subject instance to use after persistence is complete
                  - this can be the same as the method argument if the
                    underlying implementation does not need to make any Subject
                    changes
        """
        pass

    @abstractmethod
    def delete(self, subject):
        """
        Removes any persisted state for the specified Subject instance.
        This is a delete operation such that the Subject's state will not be
        accessible at a later time.

        :param subject: the Subject instance for which any persistent state
                        should be deleted
        """
        pass


# moved from /mgt:
class SubjectFactory(metaclass=ABCMeta):
    """
    A SubjectFactory is responsible for constructing Subject instances as
    needed
    """

    def create_subject(self, context):
        """
        Creates a new Subject instance reflecting the state of the specified
        contextual data.  The data would be anything required to required to
        construct a Subject instance and its contents can vary based on
        environment.

        Any data supported by Shiro core will be accessible by one of the
        SubjectContext(s) accessor properties or methods.  All other data is
        available as map attributes.

        :param context: the contextual data to be used by the implementation
                        to construct an appropriate Subject instance
        :returns: a Subject instance created based on the specified context
        """
        pass
