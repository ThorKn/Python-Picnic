from BitVector import BitVector

class Publickey:
  def __init__(self, pub_key, p):
    self.public_key = pub_key
    self.p = p

class View:
  def __init__(self, blocksize, rounds, sboxes):
    self.i_share = BitVector(intVal = 0, size = blocksize)
    self.transcript = BitVector(intVal = 0, size = 3 * rounds * sboxes)
    self.o_share = BitVector(intVal = 0, size = blocksize)

class Commitment:
  def __init__(self, hash_length, n_commitments):
    self.hashes = BitVector(intVal = 0, size = hash_length)
    self.n_commitments = n_commitments

    

