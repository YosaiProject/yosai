# Serialization
Yosai serializes objects when caching and when saving 'Remember Me' information.

The serialization process is as follows:

![serialization](img/serialization_process.png)

1. Reduce the state of a Yosai object to its primitive form (marshalling)
2. Enrich the marshalled payload with metadata
3. Encode the metadata-enriched payload


## asphalt.serialization

![asphalt_serialization](https://avatars3.githubusercontent.com/u/12229495?v=3&s=200)

Yosai uses a forked copy of the Asphalt framework's serialization library to reduce
custom classes to a primitive form that can be encoded by a serialization scheme.  

Asphalt is an asyncio based microframework for network oriented applications.  
If you would like to learn more about it, [click here](https://github.com/asphalt-framework/asphalt).

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

### Examples
To understand how to reduce objects, you are encouraged to review the serialization source code of the ``Serializable`` classes in Yosai.  The following classes are recommended for their diversity.  The serialization code is located at the bottom of each class, within the ``serialization_schema`` classmethod:

- `authz.authz.IndexedAuthorizationInfo`
- `subject.identifier.SimpleIndentifierCollection`
- `session.session.SimpleSession`
- `authz.authz.WildcardPermission`


## Serialization Manager

A ``SerializationManager`` orchestrates the serialization process.  It is indended for your caching library, wrapping "setters" with serialization and "getters" with deserialization.

For instance, the Yosai extension, ``Yosai DPCache``, obtains a SerializationManager instance during its CacheHandler initialization process.  The ``SerializationManager`` proxies all cache communication.
