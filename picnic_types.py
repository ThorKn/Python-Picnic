"""Container classes for picnic."""

from BitVector import BitVector


class Publickey(object):
    """Container for public key."""

    __slots__ = ['public_key', 'p']

    def __init__(self, pub_key, p):
        """Constructor."""
        self.public_key = pub_key
        self.p = p


class View(object):
    """Container for a players view."""

    __slots__ = ['i_share', 'transcript', 'o_share']

    def __init__(self, blocksize, rounds, sboxes):
        """Constructor."""
        self.i_share = BitVector(intVal=0, size=blocksize)
        self.transcript = BitVector(intVal=0, size=3 * rounds * sboxes)
        self.o_share = BitVector(intVal=0, size=blocksize)


class Commitment(object):
    """Container for the hash of a commitment."""

    __slots__ = ['hash', 'n_commitments']

    def __init__(self, hash_length, n_commitments):
        """Constructor."""
        self.hash = BitVector(intVal=0, size=hash_length)
        self.n_commitments = n_commitments


class Proof(object):
    """Container for a single round proof."""

    __slots__ = ['seed_1', 'seed_2', 'i_share', 'transcript', 'view_3_commit']

    def __init__(self):
        """Constructor."""
        self.seed_1 = None
        self.seed_2 = None
        self.i_share = None
        self.transcript = None
        self.view_3_commit = None


class Signature(object):
    """Container for a complete signature."""

    __slots__ = ['proofs', 'challenges', 'salt']

    def __init__(self):
        """Constructor."""
        self.proofs = None
        self.challenges = None
        self.salt = None
