import uuid
from hashlib import sha256, sha512
from yosai.core import (
    session_abcs,
)
from os import urandom


class UUIDSessionIDGenerator(session_abcs.SessionIDGenerator):

    @staticmethod
    def generate_id():
        return str(uuid.uuid4())


class RandomSessionIDGenerator(session_abcs.SessionIDGenerator):

    @staticmethod
    def generate_id():
        # session argument is ignored
        return sha256(sha512(urandom(20)).digest()).hexdigest()
