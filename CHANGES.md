v0.3
--------------
- removed authc.authc_account module
- removed all traces of DefaultCompositeAccount from authc strategies
- changed remembered-or-authenticated validation logic used during authorization
- expanded mgt.login process to support multi-factor, creating a new subject only
  after all authentication is complete
- expanded the Authenticator's role:
    - authentication sequence enforced (can't 2FA without identifiers)
    - new authentication progress event
    - added support for a "MFA Challenger" (such as SMS, GoogleAuthenticator, etc)
- authenticating realms now feature a "supported_tokens" attribute that returns
  collection of authentication token types supported
- removed the Resolver design pattern:  credential, authz_info, permission, role
- introduced lock-account workflow between Authenticator, AccountStoreRealm, and AccountStore
- removed setter side effects during realms setting
- updated cache key domains for authentication and authorization (now realm-specific)
- broadened accountstore api from get_credentials to get_authc_info
- security_manager creator now creates the credential verifiers and passes them to
  realm(s)
- realm verifiers are configurable through yosai settings
- dramatically reduced/refactored passlib authentication
- removed marshmallow from requirements
- Account is now a namedtuple
 
Yosai uses [GitHub's Releases feature](https://github.com/blog/1547-release-your-software) for its changelogs.

See [the Releases section of our GitHub project](https://github.com/YosaiProject/yosai/releases) for changelogs for each release version of Yosai.

Release announcement posts on [the official Yosai blog](http://yosaiproject.github.io/yosai) contain summaries of the most noteworthy changes made in each release.
