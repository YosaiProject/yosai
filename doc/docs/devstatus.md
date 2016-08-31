# Testing Status

# In Progress

As of Sept 2016, focus is on creating support for 2-Factor Authentication (2FA),
with special emphasis on One-Time Passwords (OTP) using secure devices such as [Nitrokey](http://www.nitrokey.com).


# Release Notes

## Release v0.2 (Sept 2016)
- Yosai can be integrated with any web application now that yosai.web development
and testing is complete.  The first web integration released is [pyramid_yosai](https://github.com/YosaiProject/pyramid_yosai).
- All authc and authz decorators are now accessible through a common interface.
- Yosai's SecurityManager is now created entirely from framework configuration
  settings.
- Serialization was dramatically changed, replacing Marshmallow with a forked
instance of Asphalt serialization.  These changes yielded *dramatic* improvements
in performance, ease of use, and type support.
