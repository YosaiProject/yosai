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
from ..meta import (
    Session,
)

from ..models.models import (
    Credential as CredentialModel,
    User as UserModel,
    Domain as DomainModel,
    Action as ActionModel,
    Resource as ResourceModel,
    Permission as PermissionModel,
    Role as RoleModel,
    role_membership as role_membership_table,
    role_permission as role_permission_table,
)

from yosai import (
    Account,
    authz_abcs,
)

from sqlalchemy import case, func
import functools


def session_context(fn):
    """
    Handles session setup and teardown
    """
    @functools.wraps(fn)
    def wrap(*args, **kwargs):
        session = Session()
        result = fn(*args, session=session, **kwargs)
        session.close()
        return result
    return wrap


# account_abcs.CredentialModelsAccountStore, account_abcs.AuthorizationAccountStore
class AlchemyAccountStore(authz_abcs.PermissionResolverAware,
                          authz_abcs.RoleResolverAware):
    """
    AccountStore provides the realm-facing API to the relational database
    that is managed through the SQLAlchemy ORM.

    step 1:  generate an orm query
    step 2:  execute the query
    step 3:  return results
    """

    def __init__(self):
        """
        Since KeyedTuple permissions records have to be converted to an object
        that yosai can use, it might as well be actual PermissionModel objects.
        """
        self._permission_resolver = None  # setter-injected after init
        self._role_resolver = None   # setter-injected after init

    @property
    def permission_resolver(self):
        return self._permission_resolver

    @permission_resolver.setter
    def permission_resolver(self, permissionresolver):
        self._permission_resolver = permissionresolver

    @property
    def role_resolver(self):
        return self._role_resolver

    @role_resolver.setter
    def role_resolver(self, roleresolver):
        self._role_resolver = roleresolver

    def get_permissions_query(self, session, identifier):
        """
        :type identifier: string
        """
        thedomain = case([(DomainModel.name == None, '*')], else_=DomainModel.name)
        theaction = case([(ActionModel.name == None, '*')], else_=ActionModel.name)
        theresource = case([(ResourceModel.name == None, '*')], else_=ResourceModel.name)

        action_agg = func.group_concat(theaction.distinct())
        resource_agg = func.group_concat(theresource.distinct())
        perm = (thedomain + ':' + action_agg + ':' + resource_agg).label("perm")

        return (session.query(perm).
                select_from(UserModel).
                join(role_membership_table, UserModel.pk_id == role_membership_table.c.user_id).
                join(role_permission_table, role_membership_table.c.role_id == role_permission_table.c.role_id).
                join(PermissionModel, role_permission_table.c.permission_id == PermissionModel.pk_id).
                outerjoin(DomainModel, PermissionModel.domain_id == DomainModel.pk_id).
                outerjoin(ActionModel, PermissionModel.action_id == ActionModel.pk_id).
                outerjoin(ResourceModel, PermissionModel.resource_id == ResourceModel.pk_id).
                filter(UserModel.identifier == identifier).
                group_by(PermissionModel.domain_id, PermissionModel.resource_id))

    def get_roles_query(self, session, identifier):
        """
        :type identifier: string
        """
        return (session.query(RoleModel).
                join(role_membership_table, RoleModel.pk_id == role_membership_table.c.role_id).
                join(UserModel, role_membership_table.c.user_id == UserModel.pk_id).
                filter(UserModel.identifier == identifier))

    def get_credential_query(self, session, identifier):
        return (session.query(CredentialModel.credential).
                join(UserModel, CredentialModel.user_id == UserModel.pk_id).
                filter(UserModel.identifier == identifier))

    @session_context
    def get_account(self, authc_token, session=None):
        """
        :param authc_token:  the request object defining the criteria by which
                             to query the account store
        :type authc_token:  AuthenticationToken

        :returns: Account
        """
        identifier = authc_token.identifier

        credential = (self.get_credential_query(session, identifier).
                      scalar().credential)

        perms = self.get_permissions_query(session, identifier).all()
        permissions = {self.permission_resolver(permission=p.perm)
                       for p in perms}

        roles = {self.role_resolver(title=r.title)
                 for r in self.get_roles_query(session, identifier).all()}

        account = Account(account_id=identifier,
                          credentials=credential,
                          permissions=permissions,
                          roles=roles)

        return account

    @session_context
    def get_credentials(self, authc_token, session=None):
        """
        :returns: Account
        """
        identifier = authc_token.identifier

        credential = self.get_credential_query(session, identifier).scalar()

        account = Account(account_id=identifier,
                          credentials=credential)

        return account

    @session_context
    def get_authz_info(self, identifier, session=None):
        """
        :returns: Account
        """

        perms = self.get_permissions_query(session, identifier).all()

        permissions = {self.permission_resolver(permission=p.perm)
                       for p in perms}

        roles = {self.role_resolver(r.title)
                 for r in self.get_roles_query(session, identifier).all()}

        account = Account(account_id=identifier,
                          permissions=permissions,
                          roles=roles)

        return account
