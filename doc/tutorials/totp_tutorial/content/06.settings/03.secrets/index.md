+++
date = "2016-11-20T14:35:16-05:00"
next = "/07.references"
prev = "/06.settings/02.totp_context"
title = "Secrets"
toc = true
weight = 63
+++

```yaml
        context:
            secrets:
                1479568656:  9xEF7DRojqkJLUENWmOoF3ZCWz3kFHylDCES92dSvYV
```

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
