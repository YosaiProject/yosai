+++
date = "2016-11-21T12:43:05-05:00"
next = "/next/path"
prev = "/prev/path"
title = "Create TOTP Factory"
toc = true
weight = 5
+++

# Create a TOTP Factory

Create a TOTP factory by passing ``create_totp_factory`` **either** an *env_var*
**or** *file_path* keyword argument, just as you do when instantiating a Yosai instance.

!! It is important that the application creating TOTP instances uses the same configuration as Yosai to verify tokens.

```python
>>> from yosai.core import create_totp_factory

# you can pass EITHER an environment_variable OR filepath:
>>> TOTPFactory = create_totp_factory(env_var='YOSAI_SETTINGS')
```
