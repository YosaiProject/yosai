+++
date = "2016-11-20T14:04:18-05:00"
next = "/next/path"
prev = "/prev/path"
title = "User-Specific Key"
toc = true
weight = 25

+++

# The User-Specific Private Key

Each user gets its own unique, private key.  This key is a 40+ character hash that
is shared between the user and application.  The application keeps this key stored
in a database in encrypted form.  The user keeps this key stored in a protected,
secure "space".  This secure "space" typically is a security-hardened USB dongle,
such as a NitroKey, or a secure space on a mobile phone accessible by an
application such as GoogleAuthenticator.

![private_key](img/private_key.jpg)
