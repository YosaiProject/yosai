+++
chapter = true
date = "2016-11-20T15:26:06-05:00"
icon = "<b>X. </b>"
next = "/next/path"
prev = "/prev/path"
title = "index"
weight = 0

+++

# One-Time Password User Setup

You will perform the following steps to enable a user for TOTP second-factor authentication:

- Generate a new TOTP instance for the user
- Create an encrypted and serialized form of the TOTP instance
- Share the private totp key, from the new TOTP instance, with the user
- Persist the encrypted private totp key to long term storage (database)

-----------------------------------------------------------------------

# Generate a new TOTP instance for the user

Create a TOTP factory by passing ``create_totp_factory`` **either** an *env_var*
**or** *file_path* keyword argument, just as you do when instantiating a Yosai instance.

** It is important that the application creating TOTP instances uses the same configuration
as Yosai uses to verify tokens.**

Generate a new TOTP instance for a user by calling TOTPFactory.new().


```python
>>> from yosai.core import create_totp_factory

# you can pass EITHER an environment_variable OR filepath:
>>> TOTPFactory = create_totp_factory(env_var='YOSAI_SETTINGS')


>>> totp = TOTPFactory.new()

>>> totp.to_dict()
{'enckey': {'c': 14,
  'k': 'FENAUW5P6VICNS6C2ODIMJT7QNJMN2RU',
  's': 'G5TMYOMHODXB2Q3IBWQQ',
  't': '1479726717783',
  'v': 1},
 'type': 'totp',
 'v': 1}

>>> totp.to_json()
'{"enckey":{"c":14,"k":"FENAUW5P6VICNS6C2ODIMJT7QNJMN2RU","s":"G5TMYOMHODXB2Q3IBWQQ","t":"1479726717783","v":1},"type":"totp","v":1}'

>>> totp.base32_key
'HXTRYI7EPSX3LVQ2EPCFQSYJIHENTG5T'
```




```python
>>> totp = TOTPFactory.new()
```
This command creates a new TOTP instance.  A TOTP instance can be initialized using
a number of arguments that are passed during the ``new`` method call above.  The
default values, however, may address your needs.

Yosai currently supports the following arguments, configuring from within the
"totp -> context" settings section of the Yosai yaml settings file.  Below is the
context config that comes packaged with Yosai.  As you can see, only secrets is
defined within context, enabling use of passlib's default values.
```yaml
    totp:
        context:
            secrets:
                1479568656:  9xEF7DRojqkJLUENWmOoF3ZCWz3kFHylDCES92dSvYV
```

* ``digits``:  The number of digits (length) of the the TOTP token, where 6 < len(digits) < 10  and default is 6
* ``alg``:  Name of hash algorithm to use. Defaults to ``"sha1"``. ``"sha256"`` and ``"sha512"`` are also accepted, per :rfc:`6238`.
* ``period``:  The number of seconds per counter step, defaults to 30 seconds
* ``label``: Label to associate with this token when generating a URI.  It is displayed to a user by most OTP client applications (e.g. Google Authenticator), and typically has format such as ``"John Smith"`` or ``"jsmith@webservice.example.org"``. Defaults to ``None``.
* ``issuer``: String identifying the token issuer (e.g. the domain name of your service). Used internally by some OTP client applications (e.g. Google Authenticator) to distinguish entries which otherwise have the same label. Optional but strongly recommended if you're rendering to a URI. Defaults to ``None``.

Unlike secrets, which is a dict, the other attributes are simple key/values:

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



# Sharing the key

The private key can be shared in a number of ways:
1) raw string (base32)
2) pretty key (base32)
2) QR Code


# Encrypting and Serializing the key



# Using the key to generate a token
