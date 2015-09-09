from yosai import (
    ThreadContext,
    UnavailableSecurityManagerException,
    DefaultSecurityManager,
    SubjectBuilder,
)


class SecurityUtils:
    def __init__(self):
        self._security_manager = DefaultSecurityManager(self)
        self.subject_builder = SubjectBuilder(self, self._security_manager)

    def get_subject(self):
        subject = ThreadContext.subject
        if (subject is None):
            subject = self.subject_builder.build_subject()
            ThreadContext.bind(subject)

    @property
    def security_manager(self):
        security_manager = ThreadContext.security_manager
        if (security_manager is None):
            security_manager = self._security_manager
            msg = "No SecurityManager accessible to the calling code."
            raise UnavailableSecurityManagerException(msg)
        return security_manager

    @security_manager.setter
    def security_manager(self, security_manager):
        self._security_manager = security_manager


security_utils = SecurityUtils()
