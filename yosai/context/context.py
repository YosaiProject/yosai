class MapContext:
    def __init__(self, context_map={}):
        """
        :type context_map: dict
        """
        super().__setattr__('context', dict(context_map))

    # entrySet:
    @property
    def attributes(self):
        return list(self.context.items())

    @property
    def values(self):
        return tuple(self.context.values())

    # yosai omits getTypedValue because of Python's dynamic typing,
    # deferring validation/exception handling up the stack
    def clear(self):
        self.context.clear() 

    # shiro size:
    def __len__(self):
        return len(self.context)

    # shiro isEmpty:
    def __nonzero__(self):
        return len(self.context) > 0

    def __contains__(self, attr):
        return attr in self.context

    # yosai omits the values-based membership version of __contains__  (TBD)

    # yosai omits nullSafePut logic until determined absolutely necessary
    # yosai omits putAll (for now)

    # shiro put:
    def __setattr__(self, attr, value):
        self.context[attr] = value

    # shiro get:
    def __getattr__(self, attr):
        return self.context.get(attr)

    # shiro remove
    def __delattr__(self, attr):
        return self.context.pop(attr)

    def __repr__(self):
        attributes = ",".join(str(key) + ': ' + str(value) 
                              for key, value in self.context.items())
        return "<Context(" + attributes + ")>"
