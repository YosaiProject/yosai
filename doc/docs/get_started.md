# Initializing Yosai
At a minimum, you must specify:
- The CacheHandler to use
- The AccountStore(s) instances from which to obtain authentication and
  authorization information
- The ``marshmallow`` serialization Schema you will use to (de)serialize
  Session state (user-defined session attributes)

Invoking ``init_yosai`` as follows will initialize Yosai within the namespace that it is called:
```Python

    from yosai.core import init_yosai, SecurityUtils

    init_yosai(cache_handler=DPCacheHandler(),
               account_stores=[AlchemyAccountStore(),
               session_schema=MySessionSchema])
```

# Authentication
```Python

    authc_token = AuthenticationToken(username='thedude',
                                      credentials='letsgobowling')

    subject = SecurityUtils.get_subject()

    subject.login(authc_token)
```


# Session Management
```Python

    subject = SecurityUtils.get_subject()

    session = subject.get_session()

    session.set_attribute('full_name', 'Jeffrey Lebowski')
```


# Authorization
```Python

    @check_permission('loan:approve')
    def approve_loan_application(self, loan_application):
        loan_application.status = 'APPROVED'
        self.notify_loan_approval(loan_application)
```
