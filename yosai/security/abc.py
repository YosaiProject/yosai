from abc import ABCMeta, abstractmethod
import base64


class ABCAbstractRememberMeManager(IRememberMeManager, metadata=ABCMeta):

    def __init__(self): 
        self.serializer = DefaultSerializer()
        self.cipher_service = AESCipherService()
        self.default_cipher_key_bytes =\
            bytearray(base64.b64decode("kPH+bIxk5D2deZiIxcaaaA=="))
        self.set_cipher_key(self.default_cipher_key_bytes)

    def getCipherKey(self):
        # Since self method should only be used with symmetric ciphers
        # (where the enc and dec keys are the same), either is fine, 
        # just return one of them:
        return self.encryption_cipher_key

    def set_cipher_key(self, cipher_key):
        # Since self method should only be used in symmetric ciphers
        # (where the enc and dec keys are the same), set it on both:
        self.encryption_cipher_key = cipher_key
        self.decryption_cipher_key = cipher_key

    @abstractmethod
    def forget_identity(sekf, subject):
        pass

    def is_remember_me(self, authc_token):
        return (authc_token is not None and 
                (isinstance(authc_token, RememberMeAuthenticationToken) and
                 (authc_token.isRememberMe())))

    def on_successful_login(self, subject, authc_token, authc_info): 
        # always clear any previous identity:
        self.forget_identity(subject)

        # now save the new identity:
        if (self.is_remember_me(authc_token)):
            self.remember_identity(subject, authc_token, authc_info)
        else:
            # log here 
            msg = ("AuthenticationToken did not indicate RememberMe is "
                   "requested.  RememberMe functionality will not be "
                   "executed for corresponding account.")
            print(msg)

    def remember_identity(self, subject, authc_token, authc_info):
        principals = self.get_identity_to_remember(subject, authc_info)
        self.remember_identity(subject, principals)

    def getIdentityToRemember(Subject subject, AuthenticationInfo info) {
        return info.getPrincipals()
    }

    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {
        byte[] bytes = convertPrincipalsToBytes(accountPrincipals)
        rememberSerializedIdentity(subject, bytes)
    }

    protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
        byte[] bytes = serialize(principals)
        if (getCipherService() != null) {
            bytes = encrypt(bytes)
        }
        return bytes
    }

    protected abstract void rememberSerializedIdentity(Subject subject, byte[] serialized)

    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        PrincipalCollection principals = null
        try {
            byte[] bytes = getRememberedSerializedIdentity(subjectContext)
            //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
            if (bytes != null && bytes.length > 0) {
                principals = convertBytesToPrincipals(bytes, subjectContext)
            }
        } catch (RuntimeException re) {
            principals = onRememberedPrincipalFailure(re, subjectContext)
        }

        return principals
    }

    protected abstract byte[] getRememberedSerializedIdentity(SubjectContext subjectContext)

    protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        if (getCipherService() != null) {
            bytes = decrypt(bytes)
        }
        return deserialize(bytes)
    }

    protected PrincipalCollection onRememberedPrincipalFailure(RuntimeException e, SubjectContext context) {
        if (log.isDebugEnabled()) {
            log.debug("There was a failure while trying to retrieve remembered principals.  This could be due to a " +
                    "configuration problem or corrupted principals.  This could also be due to a recently " +
                    "changed encryption key.  The remembered identity will be forgotten and not used for self " +
                    "request.", e)
        }
        forgetIdentity(context)
        //propagate - security manager implementation will handle and warn appropriately
        throw e
    }

    protected byte[] encrypt(byte[] serialized) {
        byte[] value = serialized
        CipherService cipherService = getCipherService()
        if (cipherService != null) {
            ByteSource byteSource = cipherService.encrypt(serialized, getEncryptionCipherKey())
            value = byteSource.getBytes()
        }
        return value
    }

    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted
        CipherService cipherService = getCipherService()
        if (cipherService != null) {
            ByteSource byteSource = cipherService.decrypt(encrypted, getDecryptionCipherKey())
            serialized = byteSource.getBytes()
        }
        return serialized
    }

    protected byte[] serialize(PrincipalCollection principals) {
        return getSerializer().serialize(principals)
    }

    protected PrincipalCollection deserialize(byte[] serializedIdentity) {
        return getSerializer().deserialize(serializedIdentity)
    }

    public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(subject)
    }

    public void onLogout(Subject subject) {
        forgetIdentity(subject)
    }
