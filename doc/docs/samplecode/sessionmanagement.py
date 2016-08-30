import collections

ShoppingCartItem = collections.namedtuple('ShoppingCartItem', 'upc title')

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
        return {'basket': {tuple(key): value for key, value in self.basket.items()}}

    def __setstate__(self, state):
        self.basket = collections.defaultdict(int)
        self.basket.update(state['basket'])


class ShoppingCartSessionManager:

    @staticmethod
    def list_items(session):
        shopping_cart = session.get_attribute('shopping_cart')
        return shopping_cart.items()

    @staticmethod
    def add_item(session, item, quantity=1):
        """
        :param item: a ShoppingCartItem namedtuple
        """
        shopping_cart = session.get_attribute('shopping_cart')
        shopping_cart.add_item(item, quantity)
        session.set_attribute('shopping_cart', shopping_cart)

    @staticmethod
    def remove_item(session, item):
        shopping_cart = session.get_attribute('shopping_cart')
        shopping_cart.remove_item(item)
        session.set_attribute('shopping_cart', shopping_cart)

if __name__ == '__main__':

    from yosai.core import Yosai

    yosai = Yosai(env_var='YOSAI_SETTINGS',
                  session_attributes=[ShoppingCart])

    with Yosai.context(yosai):

        cart = ShoppingCartSessionManager

        with Yosai.context(yosai):
          subject = Yosai.get_current_subject()
          session = subject.get_session()

          print('Empty Cart: ', my_cart.list_items())

          # ------------------------------------------------------------------------
          # Operation 1
          # ------------------------------------------------------------------------

          # could easily use functools.partial for this, but keeping it explicit
          # for the example so as to not confuse:
          cart.add_item(session, '0043000200216', 4)
          cart.add_item(session, '016000119772', 1)
          cart.add_item(session, '52159012038', 3)
          cart.add_item(session, '00028400028196', 1)

          # ------------------------------------------------------------------------
          # Operation 2
          # ------------------------------------------------------------------------

          print('Added Items: ', my_cart.list_items())
