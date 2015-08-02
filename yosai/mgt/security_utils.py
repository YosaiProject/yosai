
class SecurityUtils:
    def __init__(self):
        self._security_manager = SecurityManager()

    def get_subject(self):
        subject = ThreadContext.subject
        if (subject is None):
            subject = Subject.Builder().build_subject()
            ThreadContext.bind(subject)
   
    @property
    def security_manager(self):
        try: 
            security_manager = ThreadContext.security_manager
            if (security_manager is None):
                security_manager = self._security_manager
                msg = "No SecurityManager accessible to the calling code."
                raise UnavailableSecurityManagerException(msg)
        except UnavailableSecurityManagerException as ex:
            print(ex)
        else:
            return security_manager
        
    @security_manager.setter
    def security_manager(self, security_manager):
        self._security_manager = security_manager



