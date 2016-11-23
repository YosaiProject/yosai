+++
date = "2016-11-20T12:50:29-05:00"
next = "/01.overview/02.passlib_totp"
prev = "/01.overview"
title = "TOTP In a Nutshell"
toc = true
weight = 11

+++

Step 1:  A user submits an N-digit TOTP token to the application


Step 2: The application generates its own TOTP token and compares it with that
provided by the user.  If the tokens match, TOTP authentication is successful.
