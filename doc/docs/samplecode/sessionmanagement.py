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
        return {'basket': {'{0}|{1}'.format(key.upc, key.title): value
                           for key, value in self.basket.items()}}

    def __setstate__(self, state):
        self.basket = collections.defaultdict(int)
        for key, value in state['basket'].items():
            keys = key.split("|")
            self.basket[ShoppingCartItem(upc=keys[0], title=keys[1])] = value


class ShoppingCartSessionManager:

    @staticmethod
    def list_items(session):
        shopping_cart = session.get_attribute('shopping_cart')
        if shopping_cart:
            return shopping_cart.basket
        return None

    @staticmethod
    def add_item(session, item, quantity=1):
        """
        :param item: a ShoppingCartItem namedtuple
        """
        shopping_cart = session.get_attribute('shopping_cart')
        if shopping_cart:
            shopping_cart.add_item(item, quantity)
        else:
            shopping_cart = ShoppingCart()
            shopping_cart.add_item(item, quantity)
        session.set_attribute('shopping_cart', shopping_cart)


    @staticmethod
    def remove_item(session, item):
        shopping_cart = session.get_attribute('shopping_cart')
        if shopping_cart:
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

          print('Initial Cart Contents: ', cart.list_items(session))

          # ------------------------------------------------------------------------
          # Operation 1
          # ------------------------------------------------------------------------

          # could easily use functools.partial for this, but keeping it explicit
          # for the example so as to not confuse:
          cart.add_item(session, ShoppingCartItem(upc='0043000200216', title='guess what this is'), 4)
          cart.add_item(session, ShoppingCartItem(upc='016000119772', title='guess again'), 1)
          cart.add_item(session, ShoppingCartItem(upc='52159012038', title='can you guess'), 3)
          cart.add_item(session, ShoppingCartItem(upc='00028400028196', title='guess me'), 1)

          # ------------------------------------------------------------------------
          # Operation 2
          # ------------------------------------------------------------------------

          print('Added Items: ', cart.list_items(session))
