+++
date = "2016-11-20T14:04:10-05:00"
next = "/01.overview/05.user_key"
prev = "/01.overview/03.totp_sources"
title = "TOTP Token"
toc = true
weight = 14
+++

A TOTP token is a N-digit string, usually 6 digits in length, that can be used only
once for authentication and within a very short time window (+-30 seconds from now).
The TOTP token is generated from a private key -- a uniquely generated hash -- that
is shared between the user and application.

![totp_token](img/totp_token.png)
