+++
date = "2016-11-21T10:46:52-05:00"
next = "/06.settings/03.secrets"
prev = "/06.settings/01.dispatcher"
title = "TOTP Context"
toc = true
weight = 62

+++

A TOTP instance can be initialized using a number of arguments that are passed
during TOTP Factory initialization.  Customizing configuration is entirely optional.
The default values defined within passlib will likely address your needs.

Yosai currently supports the following attributes within the "totp -> context"
settings section of the Yosai yaml settings file.  Below is the context config
that comes packaged with Yosai.  As you can see, only secrets is defined within
context, enabling use of passlib.totp's default values.
```yaml
    totp:
        context:
            secrets:
                1479568656:  9xEF7DRojqkJLUENWmOoF3ZCWz3kFHylDCES92dSvYV
```

This is what a hypothetical configuration looks like if you were to use the
default configuration defined within passlib.totp:
```yaml
        context:
            digits: 6
            alg: sha1
            period: 30
            label: token_label_123
            issuer: my_application_name
            secrets:
                1479568656:  9xEF7DRojqkJLUENWmOoF3ZCWz3kFHylDCES92dSvYV
```
``secrets`` is the only dict.  The other attributes are simple key/values:

* ``digits``:  The number of digits (length) of the the TOTP token, where 6 < len(digits) < 10  and default is 6
* ``alg``:  Name of hash algorithm to use. Defaults to ``"sha1"``. ``"sha256"`` and ``"sha512"`` are also accepted, per :rfc:`6238`.
* ``period``:  The number of seconds per counter step, defaults to 30 seconds
* ``label``: Label to associate with this token when generating a URI.  It is displayed to a user by most OTP client applications (e.g. Google Authenticator), and typically has format such as ``"John Smith"`` or ``"jsmith@webservice.example.org"``. Defaults to ``None``.
* ``issuer``: String identifying the token issuer (e.g. the domain name of your service). Used internally by some OTP client applications (e.g. Google Authenticator) to distinguish entries which otherwise have the same label. Optional but strongly recommended if you're rendering to a URI. Defaults to ``None``.
