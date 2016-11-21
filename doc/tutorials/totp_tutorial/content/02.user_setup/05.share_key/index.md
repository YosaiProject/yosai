+++
date = "2016-11-21T12:42:35-05:00"
next = "/next/path"
prev = "/prev/path"
title = "Share TOTP Key"
toc = true
weight = 30 
+++

# Share the private totp key with the user.

How or whether you share the private totp key with the user will depend on what
facilities you want to support for TOTP authentication.  If you decide to
use SMS-based TOTP authentication, you don't ever share the private key with the user.

## Secure USB
![nitrokey_usb](images/nitrokey_renderered.jpg)

If a user is using a USB dongle, such as a Nitrokey, the hardware is accompanied
with management software that saves the private totp key to USB memory.  A user will copy/paste
the key into the software's interface and save the record to memory.
![base32_key](images/enable_twostep_authc.png)

To facilitate this method of storage, share the key as a string, either in base32 or hex format.
![nitrokey_reg](images/nitrokey_totp_registration.png)


## QR Code

![qrcode](images/enable_twostep_qrcode.png)

If a user is using a mobile application, such as Google Authenticator, the
application can read the private key as a QR code.  ``passlib.totp`` facilitates
QR code generation.  Consult [its documentation](https://passlib.readthedocs.io/en/latest/narr/totp-tutorial.html#rendering-uris) to learn how.
