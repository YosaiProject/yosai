+++
date = "2016-11-20T14:04:18-05:00"
next = "/02.user_setup"
prev = "/01.overview/04.totp_token"
title = "User-Specific Key"
toc = true
weight = 15
+++

Each user gets its own unique, private key.  This key is a 40+ character hash that
is shared between the user and application, except for sms-based totp authc.
The application keeps this key stored in a database in encrypted form.  The user
keeps this key stored in a protected, secure "space".  This secure "space" typically
is a security-hardened USB dongle, such as a NitroKey, or a secure space on a mobile
phone accessible by an application such as GoogleAuthenticator.


```python
>>> totp.base32_key
'HXTRYI7EPSX3LVQ2EPCFQSYJIHENTG5T'

>>> totp.pretty_key()
'HXTR-YI7E-PSX3-LVQ2-EPCF-QSYJ-IHEN-TG5T'

>>> totp.hex_key
'3de71c23e47cafb5d61a23c4584b0941c8d99bb3'

```
