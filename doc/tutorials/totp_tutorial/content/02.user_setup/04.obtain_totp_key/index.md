+++
date = "2016-11-21T12:42:42-05:00"
next = "/02.user_setup/05.share_key"
prev = "/02.user_setup/03.encrypt_serialize_totp"
title = "TOTP Key"
toc = true
weight = 24
+++
The TOTP instance can format the key in a few ways:  in base32, hex, or a
"pretty" base32.

```python
>>> totp.base32_key
'HXTRYI7EPSX3LVQ2EPCFQSYJIHENTG5T'

>>> totp.hex_key
'3de71c23e47cafb5d61a23c4584b0941c8d99bb3'

>>> totp.pretty_key()
'HXTR-YI7E-PSX3-LVQ2-EPCF-QSYJ-IHEN-TG5T'
```
