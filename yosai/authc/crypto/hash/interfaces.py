from abc import ABCMeta, abstractproperty
import traceback


class HashRequest(metaclass=ABCMeta):

    @abstractproperty
    def algorithm_name(self):
        pass

    @abstractproperty
    def iterations(self):
        pass
    
    @abstractproperty
    def salt(self):
        pass
    
    @abstractproperty
    def source(self):
        pass

    """ 
      A Builder class representing the Builder design pattern for constructing
      {@link HashRequest} instances.
    """ 
    class Builder(object):

        def __init__(self):
            self.iterations = 0

        def set_source(self, source):
            if isinstance(source, bytearray):
                self.source = source
            else:
                try:
                    self.source = bytearray(source) 
                except (AttributeError, TypeError):
                    traceback.print_exc()
                    raise
            return self

        def set_salt(self, salt):
            if isinstance(set, bytearray):
                self.salt = salt
            else:
                try:
                    self.salt = bytearray(salt) 
                except (AttributeError, TypeError):
                    traceback.print_exc()
                    raise
            return self

        def set_iterations(self, iterations):
            self.iterations = iterations
            return self

        def set_algorithm_name(self, algorithmname):
            self.algorithm_name = algorithmname
            return self

        def build(self):
            return SimpleHashRequest(self.algorithmName, 
                                     self.source,
                                     self.salt,
                                     self.iterations)
