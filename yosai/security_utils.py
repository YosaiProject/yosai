from yosai import (
    thread_context,
    UnavailableSecurityManagerException,
    DefaultSecurityManager,
    SubjectBuilder,
)


class SecurityUtils:
    def __init__(self):

        # This private security manager is a "backup" for obtaining a subject.
        # thread_context is the primary source for Subject instances.
        self._security_manager = DefaultSecurityManager(self)

        self.subject_builder = SubjectBuilder(self, self._security_manager)

    def get_subject(self):
        """
        Returns the currently accessible Subject available to the calling code
        depending on runtime environment

        get_subject is provided as a way to obtain a Subject without having to
        resort to implementation-specific methods.  get_subject allows the Yosai
        team to change the underlying implementation of this method in the future
        depending on requirements/updates without affecting your code that uses it.

        :returns: the Subject currently accessible to the calling code
        :raises IllegalStateException: if no Subject instance or SecurityManager
                                       instance is available to obtain a Subject
                                       (such an setup is considered an invalid
                                        application configuration because a Subject
                                        should *always* be available to the caller)
        """
        try:
            subject = thread_context.subject
        except AttributeError:
            subject = self.subject_builder.build_subject()
            thread_context.bind(subject)
        return subject

    @property
    def security_manager(self):

        # yosai refactored to make more pythonic, requires that security_manager
        # not set to None in thread_context but to raise an AttributeError
        try:
            security_manager = thread_context.security_manager
        except AttributeError:
            try:
                security_manager = self._security_manager
            except AttributeError:
                msg = "No SecurityManager accessible to the calling code."
                raise UnavailableSecurityManagerException(msg)
        return security_manager

    @security_manager.setter
    def security_manager(self, security_manager):
        """
        Sets a singleton SecurityManager, specifically for transparent use in the
        get_subject() implementation

        This method call exists mainly for framework development support.  Application
        developers should rarely, if ever, need to call this method.
        """
        self._security_manager = security_manager


security_utils = SecurityUtils()
