+++
date = "2016-11-21T12:42:52-05:00"
next = "/02.user_setup/04.obtain_totp_key"
prev = "/02.user_setup/02.generate_totp_instance"
title = "Encrypt & Serialize"
toc = true
weight = 23

+++

```python
>>> totp.to_json()
'{"enckey":{"c":14,"k":"FENAUW5P6VICNS6C2ODIMJT7QNJMN2RU","s":"G5TMYOMHODXB2Q3IBWQQ","t":"1479726717783","v":1},"type":"totp","v":1}'
```
