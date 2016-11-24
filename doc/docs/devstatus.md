# Testing Status

![](/img/core_test_coverage_nov2016.png)

![](/img/web_test_coverage_nov2016.png)


# Release Notes

## Release v0.3 (Nov 2016)
- A complete second-factor authentication workflow using time-based one-time passwords
- Rate limiting / account locking
- Significant refactoring and optimizations


## Release v0.2 (Sept 2016)
- Yosai can be integrated with any web application now that yosai.web development
and testing is complete.  The first web integration released is [pyramid_yosai](https://github.com/YosaiProject/pyramid_yosai).
- All authc and authz decorators are now accessible through a common interface.
- Yosai's SecurityManager is now created entirely from framework configuration
  settings.
- Serialization was dramatically changed, replacing Marshmallow with a forked
instance of Asphalt serialization.  These changes yielded *significant* improvements
in performance, ease of use, and type support.
