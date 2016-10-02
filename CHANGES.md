v0.3
--------------
- removed authc.authc_account module
- changed remembered-or-authenticated validation logic used during authorization
- expanded mgt.login process to support multi-factor, creating a new subject only
  after all authentication is complete
- expanded the Authenticator's role:
    - authentication sequence enforced (can't 2FA without identifiers)
    - new authentication progress event
    - added support for a "MFA Challenger" (such as SMS, GoogleAuthenticator, etc)
- authenticating realms now feature a "supported_tokens" attribute that returns
  collection of authentication token types supported

Yosai uses [GitHub's Releases feature](https://github.com/blog/1547-release-your-software) for its changelogs.

See [the Releases section of our GitHub project](https://github.com/YosaiProject/yosai/releases) for changelogs for each release version of Yosai.

Release announcement posts on [the official Yosai blog](http://yosaiproject.github.io/yosai) contain summaries of the most noteworthy changes made in each release.
