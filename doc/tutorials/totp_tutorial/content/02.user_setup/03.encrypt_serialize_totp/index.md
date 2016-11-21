+++
date = "2016-11-21T12:42:52-05:00"
next = "/next/path"
prev = "/prev/path"
title = "Encrypted, Serialized TOTP"
toc = true
weight = 5

+++

# Create an encrypted and json-serialized form of the TOTP instance

```python
>>> totp.to_json()
'{"enckey":{"c":14,"k":"FENAUW5P6VICNS6C2ODIMJT7QNJMN2RU","s":"G5TMYOMHODXB2Q3IBWQQ","t":"1479726717783","v":1},"type":"totp","v":1}'
```
