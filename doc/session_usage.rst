Session Usage and Tutorial
--------------------------
In this example, you will cache Sessions (Yosai will consequently use 
``yosai.core.session.session.CachingSessionStore``).  
If you are not using the CachingSessionStore, you are either using 
``yosai.core.session.session.MemorySessionStore`` or your own custom 
SessionStore, which is outside the scope of consideration for this documentation.  
Serialization isn't a concern if you are using in-memory session management 
as it doesn't require serialization. 

Objects are serialized before they are cached.  Yosai uses the ``marshmallow`` 
library in conjunction with an encoding library, such as MSGPack or JSON, to 
(de)serialize Serializable objects from(to) cache.  Only ``Serializable`` objects 
can be serialized.  A Serializable class implements the serialize_abcs.Serializable 
abstract base class, which requires that a ``marshmallow.Schema`` class be defined 
for implementations of it.  A Session **is** a Serializable object, therefore 
it requires its own ``marshmallow.Schema`` definition.

``marshmallow`` requires you to specify the Schema of the object and how to
properly (de)serialize it. 


.. code-block:: python
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

Example:  Shopping Cart Session Management
------------------------------------------
We'll use a web shopping cart application to illustrate how to manage state 
using a server-side Session object.

This is *not* a primer on how to write your own e-commerce shopping cart 
application.  This example is intended to illustrate the Session API. 
**It is not intended for production use.**

As per Wikipedia:::
    A shopping cart is a piece of e-commerce software on a web server that 
    allows visitors to an Internet site to select items for eventual 
    purchase... The software allows online shopping customers to *accumulate a
    list of items for purchase*, described metaphorically as “placing items in the
    shopping cart” or “add to cart.” Upon checkout, the software typically
    calculates a total for the order, including shipping and handling (i.e.,
    postage and packing) charges and the associated taxes, as applicable.

shopping_cart attribute within Session
--------------------------------------
A shopping_cart is a dict that uses a UPC product code as its key and quantity 
as its value.  


Shopping Cart
~~~~~~~~~~~~~
ShoppingCart is a facade to the Session API for managing the shopping_cart 
attribute within a Session.  

A ShoppingCart allows you to add, update, and removes items and adjust the 
quantity of each item.  

.. code-block:: python
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

.. note::
    This class is designed based on the assumption that a new ShoppingCart
    instance is obtained per request.  A Session is accessed at __init__.
    A Session is validated only when it is accessed.  If ShoppingCart were to be
    used in a web application, it would be instantiated *per request* and 
    consequently the Session would be validated per-request.

Now, you will see how your interaction with the ShoppingCart API impacts a 
user's Session.  We'll add four items to the shopping cart, remove one, and 
modify the quantity of another. 


Operation 1:  Add four items to the shopping cart
-------------------------------------------------
.. code-block:: python
    from yosai.core import SecurityUtils

    current_user = SecurityUtils.get_subject()
    my_cart = ShoppingCart(current_user)

    my_cart.add_item('0043000200216', 4)  # we'll modify the quantity of this later
    my_cart.add_item('016000119772', 1)
    my_cart.add_item('52159012038', 3)
    my_cart.add_item('00028400028196', 1)
    
    my_cart.list_items()



Operation 2:  Remove an item from the shopping cart
---------------------------------------------------
.. code-block:: python
    from yosai.core import SecurityUtils

    current_user = SecurityUtils.get_subject()
    my_cart = ShoppingCart(current_user)

    my_cart.remove_item('00028400028196')
   
     my_cart.list_items()


Operation 3:  Modify the quantity of an item in the shopping cart
-----------------------------------------------------------------
.. code-block:: python
    from yosai.core import SecurityUtils

    current_user = SecurityUtils.get_subject()
    my_cart = ShoppingCart(current_user)

    my_cart.update_item('0043000200216', 2)
   
    my_cart.list_items()
