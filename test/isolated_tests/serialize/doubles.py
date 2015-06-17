import yosai.serialize.abcs as serialize_abcs


class MockSerializable(serialize_abcs.Serializable):

    def __init__(self):
        self.myname = 'Mock Serialize'
        self.mydict = {'one': 1, 'two': 2, 'three': 3}
        self.mytuple = ('item1', 'item2')
        
    def __serialize__(self):
        return {'name': self.myname, 
                'mydict': self.mydict,
                'mytuple': self.mytuple}
