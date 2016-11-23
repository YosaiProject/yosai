+++
chapter = true
date = "2016-11-20T14:34:23-05:00"
icon = "<b>6. </b>"
next = "/06.settings/01.dispatcher"
prev = "/05.rate_limiting"
title = "Settings"
weight = 60
+++

# Yosai Settings

You can't two-factor authenticate using TOTP without configuring Yosai to support it.

All of Yosai's configuration resides within a single yaml-formatted settings file.

Include a ``totp`` section within the ``AUTHC_CONFIG`` section of this file like
so:

```yaml
AUTHC_CONFIG:

    ...

    totp:
        mfa_dispatcher: yosai_totp_sms.SMSDispatcher
        context:
            secrets:
                1479568656:  9xEF7DRojqkJLUENWmOoF3ZCWz3kFHylDCES92dSvYV
```
