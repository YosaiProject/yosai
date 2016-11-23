+++
date = "2016-11-21T12:42:58-05:00"
next = "/02.user_setup/03.encrypt_serialize_totp"
prev = "/02.user_setup/01.create_totp_factory"
title = "Generate TOTP"
toc = true
weight = 22

+++
Generate a new TOTP instance for a user by calling TOTPFactory.new().

```python
>>> totp = TOTPFactory.new()
```
