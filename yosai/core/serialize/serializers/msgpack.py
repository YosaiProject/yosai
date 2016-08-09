
# copied from asphalt-serialization

from typing import Dict, Any, Callable, Optional

from yosai.core import serialize_abcs, qualified_name
from msgpack import packb, unpackb, ExtType

from yosai.core.serialize.marshalling import default_marshaller, default_unmarshaller


class MsgpackSerializer(serialize_abcs.CustomizableSerializer):
    """
    Serializes objects using the msgpack library.

    The following defaults are passed to packer/unpacker and can be overridden by setting values
    for the options explicitly:

    * ``use_bin_type=True`` (packer)
    * ``encoding='utf-8'`` (unpacker)

    To use this serializer backend, the ``msgpack-python`` library must be installed.
    A convenient way to do this is to install ``asphalt-serialization`` with the ``msgpack``
    extra:

    .. code-block:: shell

        $ pip install asphalt-serialization[msgpack]

    .. seealso:: `Msgpack web site <http://msgpack.org/>`_

    :param packer_options: keyword arguments passed to :func:`msgpack.packb`
    :param unpacker_options: keyword arguments passed to :func:`msgpack.unpackb`
    """

    __slots__ = ('packer_options', 'unpacker_options', 'custom_type_code', '_marshallers',
                 '_unmarshallers')

    def __init__(self, packer_options: Dict[str, Any] = None,
                 unpacker_options: Dict[str, Any] = None, custom_type_code: int = 119):
        self.custom_type_code = custom_type_code
        self._marshallers = {}
        self._unmarshallers = {}

        self.packer_options = packer_options or {}
        self.packer_options.setdefault('use_bin_type', True)

        self.unpacker_options = unpacker_options or {}
        self.unpacker_options.setdefault('encoding', 'utf-8')

    def serialize(self, obj) -> bytes:
        return packb(obj, **self.packer_options)

    def deserialize(self, payload: bytes):
        return unpackb(payload, **self.unpacker_options)

    def register_custom_type(
            self, cls: type, marshaller: Optional[Callable[[Any], Any]] = default_marshaller,
            unmarshaller: Optional[Callable[[Any, Any], Any]] = default_unmarshaller, *,
            typename: str = None) -> None:
        typename = (typename or qualified_name(cls)).encode('utf-8')

        if marshaller:
            self._marshallers[cls] = typename, marshaller
            self.packer_options['default'] = self._default_encoder

        if unmarshaller:
            self._unmarshallers[typename] = cls, unmarshaller
            self.unpacker_options['ext_hook'] = self._custom_object_hook

    def _default_encoder(self, obj):
        obj_type = obj.__class__
        try:
            typename, marshaller = self._marshallers[obj_type]
        except KeyError:
            raise LookupError('no marshaller found for type "{}"'
                              .format(obj_type.__class__.__name__)) from None

        state = marshaller(obj)
        data = typename + b':' + self.serialize(state)
        return ExtType(self.custom_type_code, data)

    def _custom_object_hook(self, code: int, data: bytes):
        if code == self.custom_type_code:
            typename, payload = data.split(b':', 1)
            state = self.deserialize(payload)
            try:
                cls, unmarshaller = self._unmarshallers[typename]
            except KeyError:
                raise LookupError('no unmarshaller found for type "{}"'
                                  .format(typename.decode('utf-8'))) from None

            instance = cls.__new__(cls)
            unmarshaller(instance, state)
            return instance
        else:
            return ExtType(code, data)

    @property
    def mimetype(self):
        return 'application/msgpack'
