class ShoppingCartItemSchema(Schema):
    upc = fields.String()
    quantity = fields.Int()

# A shopping_cart is a dict that uses a UPC product code as its key and quantity 
# as its value:
class ShoppingCartSchema(Schema):
    items = fields.Nested(ShoppingCartItemSchema, many=True)

# this class is declared in case there are attributes other than a 
# shopping cart that need to be serialized:
class SessionAttributesSchema(Schema):
    shopping_cart = fields.Nested(ShoppingCartSchema)


class ShoppingCart(Serializable):
    def __init__(self, current_user):
        """
        :type current_user: subject_abcs.Subject
        """
        self.current_user = current_user
        self.session = self.current_user.get_session() 

    def list_items(self):
        shopping_cart = self.session.get_attribute('shopping_cart')
        return shopping_cart.items()

    def add_item(self, upc, quantity):
        shopping_cart = self.session.get_attribute('shopping_cart')
        shopping_cart[item] = quantity
        session.set_attribute('shopping_cart', shopping_cart)
    
    def update_item(self, upc, quantity):
        shopping_cart = self.session.get_attribute('shopping_cart')
        shopping_cart[item] = quantity
        session.set_attribute('shopping_cart', shopping_cart)

    def remove_item(self, upc):
        shopping_cart = self.session.get_attribute('shopping_cart')
        shopping_cart.pop(item)
        session.set_attribute('shopping_cart', shopping_cart)


if __name__ == '__main__':
    SecurityUtils.init_yosai(... # omitted for this example
                             ... # omitted for this example
                             session_schema=SessionAttributesSchema)

# Operation 1:  Add four items to the shopping cart
# -------------------------------------------------
    current_user = SecurityUtils.get_subject()
    my_cart = ShoppingCart(current_user)

    my_cart.add_item('0043000200216', 4)  # we'll modify the quantity of this later
    my_cart.add_item('016000119772', 1)
    my_cart.add_item('52159012038', 3)
    my_cart.add_item('00028400028196', 1)

    my_cart.list_items()


# Operation 2:  Remove an item from the shopping cart
# ---------------------------------------------------
    current_user = SecurityUtils.get_subject()
    my_cart = ShoppingCart(current_user)

    my_cart.remove_item('00028400028196')

    my_cart.list_items()


# Operation 3:  Modify the quantity of an item in the shopping cart
# -----------------------------------------------------------------
    current_user = SecurityUtils.get_subject()
    my_cart = ShoppingCart(current_user)

    my_cart.update_item('0043000200216', 2)

    my_cart.list_items()


