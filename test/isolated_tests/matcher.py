"""
    Example (make sure that Matcher is on the right of the equality check)
    ----------------------------------------------------------------------
    class Test:
        def __init__(self):
            self.one = 1
            self.two = 2
            self.three = 3

    t1 = Test()
    t2 = Test()
    m1 = ObjMatcher(t1, ['one', 'two', 'three'])
    assert t2 == m1
"""

class ObjMatcher(object):
    def __init__(self, some_obj, args):
        self.some_obj = some_obj
       
        for arg in args:
            assert hasattr(some_obj, arg)

        self.args = args  # field names (strings) that will be compared 

    def compare(self, other):
        if not type(self.some_obj) == type(other):
            return False
        for arg in self.args:
            try:
                if getattr(self.some_obj, arg) != getattr(other, arg):
                    print('attr diff:', str(getattr(self.some_obj, arg)), 
                          ' vs ', str(getattr(other, arg)))
                    return False
            except AttributeError:
                return False
        return True

    def __eq__(self, other):
        return self.compare(other)


class DictMatcher(object):
    def __init__(self, some_dict, args):
        self.some_dict = some_dict
       
        for arg in args:
            assert arg in self.some_dict

        self.args = args  # field names (strings) that will be compared 

    def compare(self, other):
        if not type(self.some_dict) == type(other):
            return False
        for arg in self.args:
            try:
                if self.some_dict[arg] != other[arg]:
                    return False
            except (KeyError, AttributeError):
                return False

        return True

    def __eq__(self, other):
        return self.compare(other)
