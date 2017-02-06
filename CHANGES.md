v0.4
--------------
- consolidated WildcardPermission and DefaultPermission to a single, more efficient
  Permission class
- introduced PermissionVerifier, configurable from yaml


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
- AuthorizationInfo abc updated
- removed EventBusAware abc, refactored how eventbus is propagated
- eliminated need for ProxiedSession (telling subject about stopped sessions)
- removed Credential class, refactored credential collection to a dict
- refactored SessionKey and WebSessionKey from class to namedtuple
- refactored SessionContext to a dict
- refactored away session and subject factories
- refactored exception handling, reducing by 85%
- replaced DefaultAuthenticationAttempt with a namedtuple
- IndexedAuthorizationInfo now stores permission strings rather than Permission instances,
  instantiating Permission instances on an as-needed basis
- permission-based authorization checks no longer supports a list of Permission instances
  as an argument but rather only list of string-typed permissions
- successful TOTP authentication raises a ConsumedTOTPToken exception
- argon2 configured as the default hashing scheme for passwords
- consolidated authorization checks to realm, eliminating authz Verifier classes
- eliminated the need for an IndexedAuthorizationInfo class by indexing permissions
  during query of account_store

Yosai uses [GitHub's Releases feature](https://github.com/blog/1547-release-your-software) for its changelogs.

See [the Releases section of our GitHub project](https://github.com/YosaiProject/yosai/releases) for changelogs for each release version of Yosai.

Release announcement posts on [the official Yosai blog](http://yosaiproject.github.io/yosai) contain summaries of the most noteworthy changes made in each release.
