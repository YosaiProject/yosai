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
from collections import defaultdict

from yosai.core import (
    RealmAttributesException,
    authc_abcs,
)


class DefaultCompositeAccountId(authc_abcs.CompositeAccountId):
    # TO-DO:  this class can easily be converted to something more pythonic..

    def __init__(self):
        self.realm_accountids = defaultdict(set)

    def get_realm_account_id(self, realm_name=None):
        return self.realm_accountids.get(realm_name, None)  # won't create new

    def set_realm_account_id(self, realm_name, accountid):
        self.realm_accountids[realm_name].add(accountid)

    def __eq__(self, other):
        if (other is self):
            return True

        if isinstance(other, DefaultCompositeAccountId):
            return self.realm_accountids == other.realm_accountids

        return False

    def __repr__(self):
        return ', '.join(["{0}: {1}".format(realm, acctids) for realm, acctids
                         in self.realm_accountids.items()])


class DefaultCompositeAccount(authc_abcs.CompositeAccount):

    def __init__(self, overwrite=True):
        self._account_id = DefaultCompositeAccountId()  # DG renamed
        self._credentials = None
        self._merged_attrs = {}
        self.overwrite = overwrite
        self._realm_attrs = defaultdict(dict)
        self._authz_info = None

    @property
    def account_id(self):
        return self._account_id

    @property
    def attributes(self):
        return self._merged_attrs

    @property
    def authz_info(self):
        return self._authz_info

    @authz_info.setter
    def authz_info(self, authzinfo):
        self._authz_info = authzinfo

    @property
    def credentials(self):
        # not needed: all accounts added to a composite have already been
        # authenticated -- included just to satisfy interface requirements
        return self._credentials

    @property
    def permissions(self):
        return self._permissions

    @property
    def roles(self):
        return self._roles

    @property
    def realm_names(self):
        return self._realm_attrs.keys()

    def append_realm_account(self, realm_name, account):

        self._account_id.set_realm_account_id(realm_name, account.account_id)

        realm_attributes = getattr(account, 'attributes', None)
        if (realm_attributes is None):
            realm_attributes = {}

        try:
            self._realm_attrs[realm_name].update(realm_attributes)
        except (AttributeError, TypeError):
            msg = 'Could not update realm_attrs using ' + str(realm_attributes)
            raise RealmAttributesException(msg)

        # attributes is a dict:
        for attribute_key, attribute_value in realm_attributes.items():
            if (self.overwrite):
                self._merged_attrs[attribute_key] = attribute_value
            else:  # write only if attribute doesn't exist yet
                if (attribute_key not in self._merged_attrs):
                    self._merged_attrs[attribute_key] = attribute_value

    def get_realm_attributes(self, realm_name):
        return self._realm_attrs.get(realm_name, dict())  # DG: no frozen dict
