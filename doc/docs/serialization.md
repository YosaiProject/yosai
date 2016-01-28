# Serialization
Yosai serializes objects when caching and when saving 'Remember Me' information.

The serialization process is as follows:

    Reduce -> Enrich -> Encode

1) Reduce the state of a Yosai object to its primitive form, as a dict
2) Enrich the payload -- that which is cached -- with metadata
3) Encode the metadata-enriched payload
    - yosai.core includes msgpack and json encoders, of which msgpack is
      the default


## Marshmallow
![](img/marshmallow-logo.png)
>Marshmallow is an ORM/ODM/framework-agnostic library for converting complex datatypes, such as objects, to and from native Python datatypes.


## Serializables
Classes that inherit from the ``Serializable`` abstract base class are eligible
for serialization in Yosai.  A Serializable class has its own marshmallow
``SerializationSchema`` class defined as an inner class of the
``serialization_schema`` classmethod.  This class is returned by the classmethod
and used during (de)serialization:

```Python
    @classmethod
    def serialization_schema(cls):

        class SerializationSchema(Schema):
            ...
        return SerializationSchema
```

To understand this requirement, you are encouraged to review the serialization
source code of the ``Serializable`` classes in Yosai.  The following classes are
recommended for their diversity.  The serialization code is located at the
bottom of each class, within the ``serialization_schema`` classmethod:
- authz.authz.IndexedAuthorizationInfo
- subject.identifier.SimpleIndentifierCollection
- session.session.SimpleSession
- authz.authz.WildcardPermission


## Serialization Manager

A ``SerializationManager`` orchestrates the serialization process.  It is indended for your caching library, wrapping "setters" with serialization and "getters" with deserialization.

For instance, the Yosai extension, ``Yosai DPCache``, obtains a SerializationManager instance during its CacheHandler initialization process.  The ``SerializationManager`` proxies all cache communication.
