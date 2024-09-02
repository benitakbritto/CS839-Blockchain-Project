import hashlib
from txn import Transaction

class Block(object):
    def __init__(self, number, transactions, previous_hash, miner):
        # constraint: should be 1 larger than the previous block
        self.number = number
        # constraint: list of transactions. Ordering matters.
        # They will be applied sequentlally.
        self.transactions = transactions
        # constraint: Should match the previous mined block's hash
        self.previous_hash = previous_hash
        # constraint: The node_identifier of the miner who mined this block
        self.miner = miner
        self.hash = self._hash()

    def _hash(self):
        return hashlib.sha256(
            str(self.number).encode("utf-8")
            + str([str(txn) for txn in self.transactions]).encode("utf-8")
            + str(self.previous_hash).encode("utf-8")
            + str(self.miner).encode("utf-8")
        ).hexdigest()

    def __str__(self) -> str:
        return "B(#%s, %s, %s, %s, %s)" % (
            self.hash[:5],
            self.number,
            self.transactions,
            self.previous_hash,
            self.miner,
        )

    def encode(self):
        encoded = self.__dict__.copy()
        encoded["transactions"] = [t.encode() for t in self.transactions]
        return encoded

    @staticmethod
    def decode(data):
        txns = [Transaction.decode(t) for t in data["transactions"]]
        return Block(data["number"], txns, data["previous_hash"], data["miner"])
