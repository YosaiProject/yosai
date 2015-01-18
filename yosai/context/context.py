from exception import IllegalArgumentException


class Context(object):

    """
    known in shiro as the MapContext, a Context is essentially a dictionary
    with a validated getter, offering type-safe attribute retrieval
    """

    def __init__(self, context_type, **kwargs):
        self._context_type = context_type
        if (kwargs):
            self.__dict__.update(**kwargs)

    def __repr__(self):
        attributes = ",".join(str(key) + ': ' + value.__class__.__name__
                              for key, value in self.__dict__.items())

        return "<Context(" + attributes + ")>"

    @property
    def context_type(self):
        return self._context_type

    def get_and_validate(self, key, cls):
        """
        Inputs:
            key = String
            cls = Class
        """
        attr = self.__dict__.get(key, None)
        if (attr):
            if isinstance(attr, cls):
                return attr
            else:
                msg = ("Object found in ContextMap under key [{0}]."
                       "Expected type is [{1}], but the object under that key"
                       "is of type [{2}]".format(key, cls.__name__,
                                                 attr.__class__.__name__))
                raise IllegalArgumentException(msg)
