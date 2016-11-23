+++
chapter = true
date = "2016-11-20T15:26:53-05:00"
icon = "<b>5. </b>"
next = "/06.settings"
prev = "/04.totp_login"
title = "Rate Limiting"
weight = 50
+++

# <center> Rate Limiting </center>

Yosai allows developers to regulate account authentication for any particular
user account by defining a number of maximum allowable authentication attempts.
If a developer defines within yosai's authentication settings an **account_lock_threshold**,
account locking is enabled, using **account_lock_threshold** as the limit.

Assuming account locking is enabled, the moment that the number of failed
authentication attempts exceeds the maximum-allowable threshold, Yosai will lock
the account, prohibiting subsequent authentication regardless of whether
credentials match.

```yaml
AUTHC_CONFIG:
    account_lock_threshold: null
```

An AccountStoreRealm obtains an account from storage.  Prior to authenticating
an account, the realm determines whether account regulation is enabled in
Yosai settings.  If account regulation is enabled, the account's locked
attribute is evaluated to determine whether an account is locked (and if so, when).

If the account is locked:
A **LockedAccountException** is raised, including a tuple containing the timestamp of
the current authentication attempt and a timestamp of when the account was locked.

If the account is not locked, authentication proceeds.

When authentication fails, Yosai caches when the failed attempt happend.  When
the total number of failed attempts exceeds the maximum allowable fails, the
account is locked in the underlying accountstore of the realm that facilitates
locking.  Consequently, failed authentication attempts live in cache until the
corresponding cache entry expires or is deleted.
