from yosai import (
    thread_local,
    UnavailableSecurityManagerException,
    SubjectBuilder,
    thread_local,
)


class SecurityUtils:

    # This private security manager is a "backup" for obtaining a subject.
    # thread_local is the primary source for Subject instances
    security_manager = None

    @classmethod
    def get_subject(cls):
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
            subject = thread_local.subject
        except AttributeError:
            subject_builder = SubjectBuilder(cls, cls.security_manager)
            subject = subject_builder.build_subject()
            thread_local.subject = subject
        return subject

    @classmethod
    def get_security_manager(cls):

        try:
            # thread_local.security_manager is set by the SubjectThreadState:
            security_manager = thread_local.security_manager
        except AttributeError:
            security_manager = cls.security_manager
            if security_manager is None:
                msg = "No SecurityManager accessible to the calling code."
                raise UnavailableSecurityManagerException(msg)
        return security_manager

    @classmethod
    def set_security_manager(cls, security_manager):
        """
        Sets a singleton SecurityManager, specifically for transparent use in the
        get_subject() implementation
        """
        cls.security_manager = security_manager
