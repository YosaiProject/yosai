# Two-Factor Authentication using Time-based One Time Passwords

![totp_logo](img/totp.jpg)

## TOTP In a Nutshell

Generate an application-specific secret key used to encrypt/decrypt user-specific keys.
When a user's key is first generated, it is encrypted prior to being persisted to
long term storage (database).  The secret key is used during every TOTP
authentication attempt.

For each user, generate a user-specific key and share it with the user, recommending
that it be kept in a trusted, secure manner. The key is a rather long string of characters.
It can be copy/pasted into a secure, trusted environment.  If you choose to use
a mobile phone to store the key, the key can be encoded into a QRCode that is read
and stored by trusted authentication apps such as Google Authenticator.

Using the application-specific secret key, encrypt the user-specific key prior
to storing it to disk.

For more information about TOTP:  https://tools.ietf.org/html/rfc6238

## Passlib 1.7

Yosai uses Passlib's totp module, available as of passlib v1.7.  Information about
this library are available from [passlib documentation](https://pythonhosted.org/passlib/)


## Client Step 1

Client is prompted to enter a username and password.  Client submits the requested
   information to the server, authenticating itself.

![username_password_login](img/username_password_login.jpg)


## Server First Authentication Request:  UsernamePasswordToken

```python
    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()

        password_token = UsernamePasswordToken(username='thedude',
                                               credentials='letsgobowling')
        try:
            new_subject.login(password_token)
        except AdditionalAuthenticationRequired:
            # this is where your application responds to the second-factor
            # request from Yosai
            # this is pseudocode:
            request_totp_token_from_client()
        except IncorrectCredentialsException:
            # incorrect username/password provided
        except LockedAccountException:
            # too many failed username/password authentication attempts, account locked
```

## Following Successful UsernamePassword Authentication

If a user is configured for two-factor authentication and username/password
is verified, Yosai signals to the calling application to collect 2FA information
from its client by raising an **AdditionalAuthenticationRequired** exception.

```python
        try:
            new_subject.login(password_token)
        except AdditionalAuthenticationRequired:
            # this is pseudocode:
            request_totp_token_from_client()
```

Additionally, Yosai will call an **MFADispatcher**, if one is configured,
to send information to the client.  One such implementation of an
**MFADispatcher** is an [SMSDispatcher](https://github.com/YosaiProject/yosai_totp_sms)
that SMS messages a client a newly-generated TOTP token (a 6-digit integer).
The Dispatcher is called prior to raising the AdditionalAuthenticationRequired exception.

![mfa_dispatcher](img/sms_totp_thumbnail.jpg)



## Client Step 2

2. Client is prompted to enter a TOTP token.  Client submits the requested
   totp token to the server, authenticating itself.

![totp_token_login](img/totp_login.jpg)



## Server Second Authentication Request:  TOTPToken

```python
    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()

        totp_token = TOTPToken(client_provided_totp_token)

        try:
            new_subject.login(totp_token)
        except IncorrectCredentialsException:
            # incorrect totp token provided
        except LockedAccountException:
            # too many failed TOTP authentication attempts, account locked
        except InvalidAuthenticationSequenceException:
            # when TOTPToken authentication is attempted prior to username/password
```

## Settings

You can't two-factor authenticate using TOTP without configuring Yosai to do so.

Within the ``AUTHC_CONFIG`` section of your Yosai yaml settings file, include a ``totp`` section.

```yaml
AUTHC_CONFIG:

    ...

    totp:
        mfa_dispatcher: yosai_totp_sms.SMSDispatcher
        context:
            secrets:
                1479568656:  9xEF7DRojqkJLUENWmOoF3ZCWz3kFHylDCES92dSvYV
```

In this example, an SMS-based dispatcher is configured for the ``mfa_dispatcher``.

``secrets`` is a key/value store containing the secret key(s) used to encrypt/decrypt
user-specific, private keys.  This secret is application-specific.  A secret key may change
periodically based on an organization's security policy.  As the secret key
changes, old secrets are kept in the ``secrets`` store so to support any user key encrypted
using an old secret.  The key used in the example below is a unix-epoch timestamp.
You can use whatever value you'd like for a key, but a unix epoch timestamp is a
good choice because it can tell anyone looking at the settings when the secret was
last generated.  The secrets key is stored with every user-specific private key
in storage so that Yosai will know which secret value was used to encrypt.



It's easy to generate the current unix epoch using the time module from the
standard library.  To generate a secret key, use the "secret generator" from passlib.totp:

```python
In [1]: import time

In [2]: from passlib.totp import generate_secret

In [3]: generate_secret()
Out[3]: '9xEF7DRojqkJLUENWmOoF3ZCWz3kFHylDCES92dSvYV'

In [4]: int(time.time())
Out[4]: 1479569669
```


## TOTP Token Sources

Secured USB:  NitroKey

Google Authenticator

SMS Message
