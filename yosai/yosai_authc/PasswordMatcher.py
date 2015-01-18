class PasswordMatcher(object):

    def __init__(self):
        self.password_service = DefaultPasswordService()

    def credentials_match(self, authc_token, account):
        service = self.ensure_password_service()

        submitted_password = self.get_submitted_password(authc_token)
        stored_credentials = self.get_stored_password(account)
        self.assert_stored_credentials_type(stored_credentials)

        if (isinstance(stored_credentials, Hash)):
            hashed_password = copy.copy(stored_credentials)
            hashingService = assertHashingPasswordService(service)
            return hashingService.passwordsMatch(submittedPassword, hashedPassword)
        }
        //otherwise they are a String (asserted in the 'assertStoredCredentialsType' method call above):
        String formatted = (String)storedCredentials
        return passwordService.passwordsMatch(submittedPassword, formatted)
    }

    def assert_hashing_password_service(self, service):
        if (service instanceof HashingPasswordService) {
            return (HashingPasswordService) service
        }
        String msg = "AuthenticationInfo's stored credentials are a Hash instance, but the " +
                "configured passwordService is not a " +
                HashingPasswordService.class.getName() + " instance.  This is required to perform Hash " +
                "object password comparisons."
        throw new IllegalStateException(msg)
    }

    def ensure_password_service(self):
        PasswordService service = getPasswordService()
        if (service == null) {
            String msg = "Required PasswordService has not been configured."
            throw new IllegalStateException(msg)
        }
        return service
    }

    def get_submitted_password(self, authc_token):
        return token != null ? token.getCredentials() : null
    }

    def assert_stored_credentials_type(self, credentials):
        if (credentials instanceof String || credentials instanceof Hash) {
            return
        }

        String msg = "Stored account credentials are expected to be either a " +
                Hash.class.getName() + " instance or a formatted hash String."
        throw new IllegalArgumentException(msg)
    }

    def get_stored_password(self, stored_account_info): 
        Object stored = storedAccountInfo != null ? storedAccountInfo.getCredentials() : null
        //fix for https://issues.apache.org/jira/browse/SHIRO-363
        if (stored instanceof char[]) {
            stored = new String((char[])stored)
        }
        return stored
    }

    def get_stored_password(self, account):
        Object stored = account != null ? account.getCredentials() : null
        //fix for https://issues.apache.org/jira/browse/SHIRO-363
        if (stored instanceof char[]) {
            stored = new String((char[])stored)
        }
        return stored
    }
