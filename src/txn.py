import uuid

class Transaction(object):
    def __init__(self, recipient, data, id=None, signature=None):
        self.recipient = recipient
        if id is None:
            self.id = uuid.uuid4().hex
        else:
            self.id = id
        # Represents data shared from sender to recipient. Can be None.
        self.data = data
        if signature is not None:
            self.signature = signature

    def set_signature(self, signature_str: str):
        self.signature = signature_str

    def __str__(self) -> str:
        return "T(%s->[%s: %s])" % (
            self.id,
            self.recipient,
            self.data,
        )

    def encode(self) -> str:
        return self.__dict__.copy()

    @staticmethod
    def decode(data):
        return Transaction(
            data["recipient"], data["data"], data["id"], data["signature"]
        )

    def __lt__(self, other):
        if self.recipient < other.recipient:
            return True
        if self.recipient > other.recipient:
            return False
        return False

    def __eq__(self, other) -> bool:
        return (
            self.recipient == other.recipient
            and self.data == other.data
            and self.id == other.id
            and self.signature == other.signature
        )
