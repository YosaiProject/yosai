Session Usage
-------------
We'll use the internals of a web shopping cart application to illustrate how to 
manage state during a user's shopping experience.  A shopping cart resides in 
the user's Session and so therefore is a good example to work with.

This is *not* a primer on how to write your own e-commerce shopping cart 
application.  The intention of this example is to illustrate the Session API.  

As per Wikipedia:::
    A shopping cart is a piece of e-commerce software on a web server that 
    allows visitors to an Internet site to select items for eventual 
    purchase... The software allows online shopping customers to *accumulate a
    list of items for purchase*, described metaphorically as “placing items in the
    shopping cart” or “add to cart.” Upon checkout, the software typically
    calculates a total for the order, including shipping and handling (i.e.,
    postage and packing) charges and the associated taxes, as applicable.


Shopping Cart Data Model
~~~~~~~~~~~~~~~~~~~~~~~~
A shopping cart is a mini-inventory management system in that it allows you to add, 
update, and removes items and allows you to adjust the quantity of each item.

Let's see how a user could add, update, and remove items from the shopping cart,
within a Session.

For this example, We'll use a simple Python class that contains a dict representing 
the shopping cart, whose key is the UPC product code of the item and value is 
quantity.  

A Session is a Serializable object in Yosai.  Yosai uses the ``marshmallow`` library
in conjunction with an encoding library, such as MSGPack or JSON, to (de)serialize
Serializable objects from cache.  If you are not using the CachingSessionStore,
you are using the MemorySessionStore.  The in-memory MemorySessionStore doesn't
require serialization.  This example assumes that you are using cache-enabled 
Session storage.

``marshmallow`` requires you to specify the Schema of the object and how to
properly (de)serialize it. 

.. code-block:: python
    from marshmallow import Schema, fields

    class ShoppingCart(Serializable):
        def __init__(self):
            self.items = {}  # collects shopping cart items
    
        def add_item(self, upc, quantity):
            self.items[item] = quantity
        
        def update_item(self, upc, quantity):
            self.items[item] = quantity

        def remove_item(self, upc):
            self.items.pop(item)

    class ShoppingCartItemSchema(Schema):
        upc = fields.String()
        quantity = fields.Int()

    class ShoppingCartSchema(Schema):
        items = fields.Nested(ShoppingCartItemSchema, many=True)
  
    # this class is declared in case there are attributes other than a 
    # shopping cart that need to be serialized:
    class SessionAttributesSchema(Schema):
        shopping_cart = fields.Nested(ShoppingCartSchema)


the ``SessionAttributesSchema`` class is passed as an argument during Yosai
initialization:

.. code-block:: python

    SecurityUtils.init_yosai(... # omitted for this example
                             ... # omitted for this example
                             session_schema=SessionAttributesSchema)

We'll add four items to the shopping cart, delete one, and modify the quantity 
of another.  This is what our final cart will look like:

.. code-block:: python
    items = {'0043000200216': 2,
             '016000119772': 1,
             '52159012038':3}

set_attribute
remove_attribute


