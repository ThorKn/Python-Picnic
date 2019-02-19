import os
from BitVector import BitVector
import hashlib

from lowmc import LowMC
from picnic_types import *

class Picnic:

  def __init__(self):
    self.blocksize = 128
    self.blocksize_bytes = int(self.blocksize / 8)
    self.keysize = 128
    self.rounds = 20
    self.sboxes = 10
    self.mpc_rounds = 219
    self.hash_length = 256
    self.lowmc = LowMC('picnic-L1')

    self.__priv_key = None
    self.__pub_key = None  
    self.__views = []
    self.__commitments = []
    self.__seeds = []
    self.__salt = None

  # Signing a message
  # @param message as bytes
  def sign(self, message):

    # Initialize views
    for _ in range(self.mpc_rounds):
      three_views = []
      for _ in range(3):
        single_view = View(self.blocksize, self.rounds, self.sboxes)
        three_views.append(single_view)
      self.__views.append(three_views)

    # Initialize commitments
    for _ in range(self.mpc_rounds):
      three_commits = []
      for _ in range(3):
        single_commit = Commitment(self.hash_length, 0)
        three_commits.append(single_commit)
      self.__commitments.append(three_commits)

    # Initialize seeds
    # Get one long shake_128 hash with length (3 * mpc_rounds + 1) * (blocksize / 8)
    # and split it afterwards into seeds and one salt
    shake128 = hashlib.shake_128()
    shake128.update(bytes.fromhex(self.__priv_key.get_bitvector_in_hex()))
    shake128.update(message)
    shake128.update(bytes.fromhex(self.__pub_key.public_key.get_bitvector_in_hex()))
    shake128.update(bytes.fromhex(self.__pub_key.p.get_bitvector_in_hex()))
    shake128.update(bytes([self.blocksize, 0]))
    long_hash = shake128.digest(((3 * self.mpc_rounds) + 1) * self.blocksize_bytes)

    count = 0
    for _ in range(self.mpc_rounds):
      three_seeds = []
      for _ in range(3):
        single_seed = BitVector(rawbytes = long_hash[count:count + self.blocksize_bytes])
        count += self.blocksize_bytes
        three_seeds.append(single_seed)
      self.__seeds.append(three_seeds)
    self.__salt = BitVector(rawbytes = long_hash[count:count + self.blocksize_bytes])

    # MPC Rounds
    for t in range(self.mpc_rounds):
      tapes = []

      # Create tapes[0..2] and i_shares
      for j in range(2):
        length = int((self.blocksize + 3 * self.rounds * self.sboxes) / 8)
        tmp = self.create_random_tape(t, j, length)
        self.__views[t][j].i_share = BitVector(rawbytes = tmp[0:self.blocksize_bytes])
        tapes.append(BitVector(rawbytes = tmp[self.blocksize_bytes:length]))

        '''
        print("views[" + str(t) + "][" + str(j) + "].ishare : " + self.__views[t][j].i_share.get_bitvector_in_hex().upper())      
        print("tapes[" + str(j) + "] : " + tapes[j].get_bitvector_in_hex().upper())
        '''

      length = int((3 * self.rounds * self.sboxes) / 8)
      tmp = self.create_random_tape(t, 2, length)
      tapes.append(BitVector(rawbytes = tmp))
      self.__views[t][2].i_share = self.__priv_key ^ \
                                   self.__views[t][0].i_share ^ \
                                   self.__views[t][1].i_share

      '''
      print("views[" + str(t) + "][2].ishare : " + self.__views[t][2].i_share.get_bitvector_in_hex().upper())      
      print("tapes[2] : " + tapes[2].get_bitvector_in_hex().upper())
      '''
    
      # Run MPC
      


  def create_random_tape(self, mpc_round, player, length):

    # H2(seed[mpc_round][player])
    shake128 = hashlib.shake_128()
    shake128.update(bytes([0x02]))
    shake128.update(bytes.fromhex(self.__seeds[mpc_round][player].get_bitvector_in_hex()))
    h2 = shake128.digest(int(self.hash_length / 8))

    # Create random tape
    shake128 = hashlib.shake_128()
    shake128.update(h2)
    shake128.update(bytes.fromhex(self.__salt.get_bitvector_in_hex()))
    shake128.update(bytes([mpc_round, 0]))
    shake128.update(bytes([player, 0]))
    length_le = length.to_bytes(2, byteorder='little')
    shake128.update(length.to_bytes(2, byteorder='little'))

    return shake128.digest(length)


  def generate_keys(self, p = None, priv_key = None):

    # Generate random p with length self.keysize
    if (p is None):
      raw_p = os.urandom(int(self.keysize / 8))
    else:
      raw_p = p
    bitvector_p = BitVector(rawbytes = raw_p)
  
    # Generate private key with length self.keysize
    if (priv_key is None):
      raw_priv_key = os.urandom(int(self.keysize / 8))    
    else:
      raw_priv_key = priv_key
    self.__priv_key = BitVector(rawbytes = raw_priv_key)

    # Generate public key [c,p]
    self.lowmc.set_priv_key(raw_priv_key)
    raw_c = self.lowmc.encrypt(raw_p)
    bitvector_c = BitVector(rawbytes = raw_c)
    self.__pub_key = Publickey(bitvector_c, bitvector_p)

    
def main():
  picnic = Picnic()
  priv_key = bytes([0xA5, 0x2A, 0x6C, 0x86, 0xC2, 0x9A, 0x19, 0x3B, 0x42, 0xE9, 0x97, 0xAC, 0xAC, 0xB2, 0x66, 0x03])  
  p        = bytes([0x95, 0xB3, 0xB0, 0x21, 0x8B, 0x6D, 0xFE, 0xEE, 0x04, 0x9D, 0xF0, 0x22, 0x6E, 0x5B, 0xB5, 0xEA])
  picnic.generate_keys(p = p, priv_key = priv_key)

  message = bytearray([0x01] * 500)
  picnic.sign(message)


if __name__ == '__main__':
    main()
