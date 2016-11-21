+++
date = "2016-11-21T12:42:42-05:00"
next = "/next/path"
prev = "/prev/path"
title = "Obtain TOTP Key"
toc = true
weight = 25
+++

# Obtain the private totp key

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
