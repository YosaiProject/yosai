+++
chapter = true
date = "2016-11-20T15:26:06-05:00"
icon = "<b>X. </b>"
next = "/next/path"
prev = "/prev/path"
title = "TOTP Setup"
weight = 0
+++

# One-Time Password User Setup

You will perform the following steps to enable a user for TOTP second-factor authentication:
- Create a TOTP Factory
- Use the TOTP Factory to generate a new TOTP instance
- Create an encrypted and json-serialized form of the TOTP instance
- Obtain the private totp key
- Share the private totp key with the user
- Persist the encrypted, serialize TOTP key to long term storage (database)
