Serialization
=============
Yosai serializes objects when caching and when saving 'Remember Me' information.

The serialization process is as follows:

    Reduce -> Enrich -> Encode

    1) Reduce the state of a Yosai object to its primitive form, as a dict
    2) Enrich the payload -- that which is cached -- with metadata
    3) Encode the metadata-enriched payload
        - yosai.core includes msgpack and json encoders, of which msgpack is
          the default

Serializables
-------------
Classes that inherit from the ``Serializable`` abstract base class are eligible
for serialization in Yosai.  Each Serializable class is expected to have its own
marshmallow ``Schema`` class defined as an inner class, keeping the schema
definition close to the class that it represents.


Serialization Manager
---------------------
A ``SerializationManager`` orchestrates the serialization process.  It is indended for
the caching library that you choose, serializing and de-serializing transmissions.

The Yosai extension, ``Yosai DPCache``, obtains a SerializationManager instance
during its CacheHandler initialization process.
