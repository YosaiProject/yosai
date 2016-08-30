import collections
from yosai.core import SerializationManager


class ShoppingCart:
    def __init__(self):
        self.basket = collections.defaultdict(int)

    def add_item(self, item, quantity=1):
        """
        :param item: a ShoppingCartItem namedtuple
        :type quantity: int
        """
        self.basket[item] += quantity

    def remove_item(self, item):
        """
        :param item: a ShoppingCartItem namedtuple
        """
        self.basket.pop(item)

    def __getstate__(self):
        # defaultdict isn't supported for marshalling, so convert it:
        return {'basket': {'{0}|{1}'.format(key.upc, key.title): value
                           for key, value in self.basket.items()}}

    def __setstate__(self, state):
        self.basket = collections.defaultdict(int)
        for key, value in state['basket'].items():
            keys = key.split("|")
            self.basket[ShoppingCartItem(upc=keys[0], title=keys[1])] = value


cart = ShoppingCart()
ShoppingCartItem = collections.namedtuple('ShoppingCartItem', 'upc title')
cart.add_item(ShoppingCartItem(upc='upc_code_123', title='testing 123'))
cart.add_item(ShoppingCartItem(upc='upc_code_456', title='testing 456'))

sm = SerializationManager([ShoppingCart], 'json')
serialized = sm.serialize(cart)

deserialized = sm.deserialize(serialized)


