from yosai.serialize import abcs as serialize_abcs


class MapContext(serialize_abcs.Serializable):
    """
    a dict with a few more features
    """
    def __init__(self, context_map={}):
        """
        :type context_map: dict
        """
        self.context = dict(context_map)

    # entrySet:
    @property
    def attributes(self):
        return list(self.context.items())
    
    @property
    def is_empty(self):
        return len(self.context) == 0

    @property
    def values(self):
        return tuple(self.context.values())

    # yosai omits getTypedValue because of Python's dynamic typing and to
    # defer validation/exception handling up the stack

    def clear(self):
        self.context.clear() 

    def size(self):
        return len(self.context)

    # key-based membership check:
    def __contains__(self, attr):
        return attr in self.context

    # yosai omits the values-based membership version of __contains__  (TBD)

    # yosai omits putAll (for now)

    def put(self, attr, value):
        self.context[attr] = value

    # shiro nullSafePut:
    def none_safe_put(self, attr, value):
        if value:
            self.context[attr] = value

    def get(self, attr):
        return self.context.get(attr, None)

    def remove(self, attr):
        return self.context.pop(attr, None)

    def __repr__(self):
        attributes = ", ".join(str(key) + ': ' + str(value) 
                               for key, value in self.context.items())
        return "<" + self.__class__.__name__ + "(" + attributes + ")>"

    def __serialize__(self):
        return self.context
