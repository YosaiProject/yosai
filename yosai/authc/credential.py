import passlib
import traceback


class DefaultPasswordService(object):

    def __init__(self):
        self.default_hash_algorithm = "SHA-256"
        self.default_hash_iterations = 500000
        self.hash_format_warned = False  # used to avoid excessive log noise

        hash_service = DefaultHashService()
        hash_service.hash_algorithm_name = self.default_hash_algorithm
        hash_service.hash_iterations = self.default_hash_iterations
        hash_service.generate_public_salt = True  # always want generated salts
        self.hash_service = hash_service

        self.hash_format = Shiro1CryptFormat()
        self.hash_format_factory = DefaultHashFormatFactory()

    def encrypt_password(self, plaintext):
        hashed = self.hash_password(plaintext)
        self.check_hash_format_durability()
        return self.hash_format.format(hashed)
    
    def hash_password(self, plaintext):
        plaintext_bytes = self.create_byte_source(plaintext)
        if (not plaintext_bytes):
            return None 
        request = self.create_hash_request(plaintext_bytes)
        return hash_service.compute_hash(request)

    def passwords_match(self, plaintext, saved):
        """
        :type plaintext:
        :param plaintext: the password requiring authentication, passed by user

        :type saved: Hash or str
        :param saved: the password saved for the corresponding account

        :returns: a Boolean confirmation of whether plaintext equals saved
        :rtype: bool
        """

        if isinstance(saved, Hash):

            plaintext_bytes = self.create_byte_source(plaintext)

            if (not saved):
                return (not plaintext_bytes)
            else:
                if (not plaintext_bytes):
                    return False

            request = self.build_hash_request(plaintext_bytes, saved)

            computed = self.hash_service.compute_hash(request)

            return saved.equals(computed)
    
        elif isinstance(saved, str): 
            plaintext_bytes = self.create_byte_source(plaintext)

            if (not saved):
                return (not plaintext_bytes)
            else: 
                if (not plaintext_bytes):
                    return False

            """
            First check to see if we can reconstitute the original hash - self
            allows us to perform password hash comparisons even for previously
            saved passwords that don't match the current HashService 
            configuration values.  This is a very nice feature for password
            comparisons because it ensures backwards compatibility even after
            configuration changes.
            """
            discovered_format = self.hash_format_factory.get_instance(saved)

            if (discovered_format):
                try:
                    saved_hash = discovered_format.parse(saved)
                except:
                    raise
                return self.passwords_match(plaintext, saved_hash)

            """
            If we're at self point in the method's execution, We couldn't
            reconstitute the original hash.  So, we need to hash the
            submittedPlaintext using current HashService configuration and then
            compare the formatted output with the saved string.  This will
            correctly compare passwords, but does not allow changing the
            HashService configuration without breaking previously saved 
            passwords:
        
            The saved text value can't be reconstituted into a Hash instance.
            We need to format the submittedPlaintext and then compare self
            formatted value with the saved value: 
            """
            request = self.create_hash_request(plaintext_bytes)
            computed = self.hash_service.compute_hash(request)
            formatted = self.hash_format.format(computed)

            return (saved == formatted)

    def check_hash_format_durability(self):

        if (not self.hash_format_warned):

            format = copy.copy(self.hash_format)

            if (not isinstance(format, ParsableHashFormat)):
                # log here
                msg = ("The configured hashFormat instance [" +
                       format.__class__.__name__ + "] is not a " 
                       "ParsableHashFormat implementation.  This is "
                       "required if you wish to support backwards "
                       "compatibility for saved password checking (almost " 
                       "always desirable). Without a ParsableHashFormat "
                       "instance, any hash_service configuration changes will"
                       "break previously hashed/saved passwords.")
                print(msg) 
                self.hash_format_warned = True

    def create_hash_request(self, plaintext):
        return HashRequest.Builder().set_source(plaintext).build()

    def create_byte_source(self, target_object):
        return bytearray(bytes(target_object))

    def build_hash_request(self, plaintext, saved):
        # keep everything from the saved hash except for the source:
        # now use the existing saved data:
        return HashRequest.Builder().set_source(plaintext).\
                set_algorithm_name(saved.algorithm_name).\
                set_salt(saved.salt).\
                set_iterations(saved.iterations).\
                build()


class SimpleCredentialsMatcher(object):

    def __init__(self):
        pass

    def get_credentials(self, credential_source):
        """
        :type credential_source: an AuthenticationToken or Account object
        :param credential_source:  an object that manages state of credentials
        """
        try:
            return credential_source.credentials
        except (AttributeError, TypeError):
            traceback.print_exc()
            return None 

    def credentials_match(self, authc_token, account):
        try:
            return authc_token.credentials == account.credentials
        except (AttributeError, TypeError):
            traceback.print_exc()
            return False


class AllowAllCredentialsMatcher(object):

    def credentials_match(self, authc_token, account):
        return True
