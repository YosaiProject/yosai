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
from collections import namedtuple

from yosai.core import (
    IncorrectCredentialsException,
    MultiRealmAuthenticationException,
)

AuthenticationAttempt = namedtuple('AuthenticationAttempt',
                                          'authentication_token, realms')


def all_realms_successful_strategy(authc_attempt):
    token = authc_attempt.authentication_token
    account = None
    for realm in authc_attempt.realms:
        if (realm.supports(token)):
            """
            If the realm raises an exception, the loop will short
            circuit, propagating the IncorrectCredentialsException
            further up the stack.  As an 'all successful' strategy, if
            there is even a single exception thrown by any of the
            supported realms, the authentication attempt is
            unsuccessful.  This particular implementation also favors
            short circuiting immediately (instead of trying
            all realms and then aggregating all potential exceptions)
            because continuing to access additional account stores is
            likely to incur unnecessary / undesirable I/O for most apps
            """
            # an IncorrectCredentialsException halts the loop:
            account = realm.authenticate_account(token)
    return account


def at_least_one_realm_successful_strategy(authc_attempt):

    authc_token = authc_attempt.authentication_token
    realm_errors = []
    account = None
    for realm in authc_attempt.realms:
        if (realm.supports(authc_token)):
            try:
                account = realm.authenticate_account(authc_token)
            except IncorrectCredentialsException as ex:
                realm_errors.append(ex)

    if (realm_errors):  # if no successful authentications
        raise MultiRealmAuthenticationException(realm_errors)

    return account


def first_realm_successful_strategy(authc_attempt):
    """
     The FirstRealmSuccessfulStrategy will iterate over the available realms
     and invoke Realm.authenticate_account(authc_token) on each one. The moment
     that a realm returns an Account without raising an Exception, that account
     is returned immediately and all subsequent realms ignored entirely
     (iteration 'short circuits').

     If no realms return an Account:
         * If only one exception was thrown by any consulted Realm, that
           exception is thrown.
         * If more than one Realm threw an exception during consultation, those
           exceptions are bundled together as a
           MultiRealmAuthenticationException and that exception is thrown.
         * If no exceptions were thrown, None is returned, indicating to the
           calling Authenticator that no Account was found (for that token)

    :type authc_attempt:  AuthenticationAttempt
    :returns:  Account
    """
    authc_token = authc_attempt.authentication_token
    realm_errors = []
    account = None
    for realm in authc_attempt.realms:
        if (realm.supports(authc_token)):
            try:
                account = realm.authenticate_account(authc_token)
            except Exception as ex:
                realm_errors.append(ex)
            if (account):
                    return account

    if (realm_errors):
        if (len(realm_errors) == 1):
            raise realm_errors[0]

        else:
            raise MultiRealmAuthenticationException(realm_errors)

    return None  # implies account was not found for token
