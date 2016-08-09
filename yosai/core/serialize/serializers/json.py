
# copied from asphalt-serialization

from yosai.core import serialize_abcs, resolve_reference, qualified_name
from collections import OrderedDict
from json.decoder import JSONDecoder
from json.encoder import JSONEncoder
from typing import Dict, Any, Callable, Optional

from yosai.core.serialize.marshalling import default_marshaller, default_unmarshaller


class JSONSerializer(serialize_abcs.CustomizableSerializer):
    """
    Serializes objects using JSON (JavaScript Object Notation).

    See the :mod:`json` module documentation in the standard library for more information on
    available options.

    Certain options can resolve references to objects:

    * ``encoder_options['default']``
    * ``decoder_options['object_hook']``
    * ``decoder_options['object_pairs_hook']``

    :param encoder_options: keyword arguments passed to :class:`~json.JSONEncoder`
    :param decoder_options: keyword arguments passed to :class:`~json.JSONDecoder`
    :param encoding: the text encoding to use for converting to and from bytes
    :param custom_type_key: magic key that identifies custom types in a JSON object
    """

    __slots__ = ('encoder_options', 'decoder_options', 'encoding', 'custom_type_key', '_encoder',
                 '_decoder', '_marshallers', '_unmarshallers')

    def __init__(self, encoder_options: Dict[str, Any] = None,
                 decoder_options: Dict[str, Any] = None, encoding: str = 'utf-8',
                 custom_type_key: str = '__type__'):
        self.encoding = encoding
        self.custom_type_key = custom_type_key
        self._marshallers = OrderedDict()  # class -> (typename, marshaller function)
        self._unmarshallers = OrderedDict()  # typename -> (class, unmarshaller function)

        self.encoder_options = encoder_options or {}

        self.encoder_options['default'] = resolve_reference(self.encoder_options.get('default'))
        self._encoder = JSONEncoder(**self.encoder_options)

        self.decoder_options = decoder_options or {}
        self.decoder_options['object_hook'] = resolve_reference(
            self.decoder_options.get('object_hook'))
        self.decoder_options['object_pairs_hook'] = resolve_reference(
            self.decoder_options.get('object_pairs_hook'))
        self._decoder = JSONDecoder(**self.decoder_options)

    def serialize(self, obj) -> bytes:
        return self._encoder.encode(obj).encode(self.encoding)

    def deserialize(self, payload: bytes):
        payload = payload.decode(self.encoding)
        return self._decoder.decode(payload)

    def register_custom_type(
            self, cls: type, marshaller: Optional[Callable[[Any], Any]] = default_marshaller,
            unmarshaller: Optional[Callable[[Any, Any], Any]] = default_unmarshaller, *,
            typename: str = None) -> None:
        typename = typename or qualified_name(cls)
        if marshaller:
            self._marshallers[cls] = typename, marshaller
            self.encoder_options['default'] = self._default_encoder
            self._encoder = JSONEncoder(**self.encoder_options)

        if unmarshaller:
            self._unmarshallers[typename] = cls, unmarshaller
            self.decoder_options['object_hook'] = self._custom_object_hook
            self._decoder = JSONDecoder(**self.decoder_options)

    def _default_encoder(self, obj):
        obj_type = obj.__class__
        try:
            typename, marshaller = self._marshallers[obj_type]
        except KeyError:
            raise LookupError('no marshaller found for type "{}"'
                              .format(obj_type.__class__.__name__)) from None

        state = marshaller(obj)
        return {self.custom_type_key: typename, 'state': state}

    def _custom_object_hook(self, obj: Dict[str, Any]):
        if len(obj) == 2 and self.custom_type_key in obj:
            typename = obj[self.custom_type_key]
            try:
                cls, unmarshaller = self._unmarshallers[typename]
            except KeyError:
                raise LookupError('no unmarshaller found for type "{}"'.format(typename)) from None

            instance = cls.__new__(cls)
            unmarshaller(instance, obj['state'])
            return instance
        else:
            return obj

    @property
    def mimetype(self):
        return 'application/json'
