from yosai import (
    DefaultSubjectContext,
    IllegalArgumentException,
)


class SubjectBuilder:

    def __init__(self,
                 securitymanager,
                 subjectcontext=None,
                 host=None,
                 sessionid=None,
                 session=None,
                 identifiers=None,
                 session_creation_enabled=True,
                 authenticated=False,
                 **context_attributes):

        self.security_manager  = securitymanager # security_utils.security_manager

        if subjectcontext is None:
            self.subject_context = DefaultSubjectContext()

        try:
            self.subject_context.security_manager = self.security_manager
        except AttributeError:
            msg = ("Subject cannot initialize without a SecurityManager "
                   "and a SubjectContext")
            raise IllegalArgumentException(msg)

        self.subject_context.host = host
        self.subject_context.session_id = sessionid
        self.subject_context.session = session
        self.subject_context.identifers = identifiers
        self.subject_context.set_session_creation_enabled = session_creation_enabled
        self.subject_context.authenticated = authenticated

        for key, val in context_attributes.items():
            self.context_attribute(key, val)

    def context_attribute(self, attribute_key, attribute_value):

        """
        Allows custom attributes to be added to the underlying context Map used
        to construct the Subject instance.

        A None key throws an IllegalArgumentException.
        A None value effectively removes any previously stored attribute under
        the given key from the context map.

        NOTE: This method is only useful when configuring Yosai with a custom
        SubjectFactory implementation.  This method allows end-users to append
        additional data to the context map which the SubjectFactory
        implementation can use when building custom Subject instances. As such,
        this method is only useful when a custom SubjectFactory implementation
        has been configured.

        :param attribute_key:  the key under which the corresponding value will
                               be stored in the context Map
        :param attribute_value: the value to store in the context map under the
                                specified attribute_key
        :raises IllegalArgumentException: if the attribute_key is None
        """
        if (not attribute_key):
            msg = "Subject context map key cannot be None"
            raise IllegalArgumentException(msg)
        if (not attribute_value):
            self.subject_context.remove(attribute_key)
        else:
            self.subject_context.put(attribute_key, attribute_value)

    def build_subject(self):
        return self.security_manager.create_subject(self.subject_context)
