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
    self.__tapes_pos = 0
    self.__challenges = None
    self.__prove = None
    self.__signature = Signature()

  ##########################
  ###   Sign and verify  ###
  ##########################

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

    # A hack for the last 5 bytes of the tmp_view_raw is needed
    # and this seems as a bug (or unwanted behaviour) in the ref-sourcecode so far.
    new_end_of_tmp_view = bytearray([0,0,0,0,0])

    # MPC Rounds
    for t in range(self.mpc_rounds):

      print("MPC round " + str(t))

      tapes = []
      self.__tapes_pos = 0

      # Create tapes[0..2] and i_shares
      for j in range(2):
        length = int((self.blocksize + 3 * self.rounds * self.sboxes) / 8)
        tmp_view_raw = self.mpc_create_random_tape(t, j, length) + new_end_of_tmp_view
        self.__views[t][j].i_share = BitVector(rawbytes = tmp_view_raw[0:self.blocksize_bytes])
        tapes.append(BitVector(rawbytes = tmp_view_raw[self.blocksize_bytes:length]))

      length_2 = int((3 * self.rounds * self.sboxes) / 8)
      tapes.append(BitVector(rawbytes = self.mpc_create_random_tape(t, 2, length_2)))
      self.__views[t][2].i_share = self.__priv_key ^ \
                                   self.__views[t][0].i_share ^ \
                                   self.__views[t][1].i_share

      # Run MPC
      new_end_of_tmp_view = self.run_mpc(t, tapes, tmp_view_raw);

      # Calculate the commitments
      self.mpc_commit(t)

    # Calculate challenges
    self.__challenges = self.h3(message)

    # Calculate proofs
    self.__proofs = self.prove()

    # Copy proofs, challenges and salt to self.__signature
    self.__signature.proofs = self.__proofs
    self.__signature.challenges = self.__challenges
    self.__signature.salt = self.__salt
  
  ##############################
  ###   LowMC MPC functions  ###
  ##############################

  # Simulate LowMC for all three players
  def run_mpc(self, t, tapes, tmp_view_raw):

    key_shares = []
    states = []
    roundkeys = []

    # Create empty roundkeys and states
    # Fill key_shares with views
    for i in range(3):
      roundkeys.append(BitVector(intVal = 0, size = self.blocksize))
      states.append(BitVector(intVal = 0, size = self.blocksize))
      key_shares.append(self.__views[t][i].i_share)
    
    # Init states by xor'ing plaintext and roundkeys
    states = self.mpc_xor_constant(states, self.__pub_key.p)
    roundkeys = self.lowmc.mpc_matrix_mul_keys(roundkeys, key_shares, 0)
    states = self.mpc_xor(states, roundkeys)

    for r in range(self.rounds):

      states = self.mpc_sbox(states, tapes, r, t)
      states = self.lowmc.mpc_matrix_mul_lin(states, states, r)
      states = self.lowmc.mpc_xor_rconsts(states, r)
      roundkeys = self.lowmc.mpc_matrix_mul_keys(roundkeys, key_shares, r + 1)
      states = self.mpc_xor(states, roundkeys)

    for i in range(3):
      self.__views[t][i].o_share = states[i]
      
    '''
    for i in range(3):
      print("state " + str(i) + ": " + states[i].get_bitvector_in_hex())
    for i in range(3):
      print("transcript " + str(i) + ": " + self.__views[t][i].transcript.get_bitvector_in_hex())
    '''

    # This is part of a hack for the end of tmp_view_raw
    new_end_of_tmp_view = bytes.fromhex(states[2][self.blocksize - 40:self.blocksize].get_bitvector_in_hex())

    return new_end_of_tmp_view

  # MPC LowMC sbox for signing
  def mpc_sbox(self, states, tapes, r, t):

    a = (BitVector(intVal = 0, size = 3))
    b = (BitVector(intVal = 0, size = 3))
    c = (BitVector(intVal = 0, size = 3))
    ab = (BitVector(intVal = 0, size = 3))
    bc = (BitVector(intVal = 0, size = 3))
    ca = (BitVector(intVal = 0, size = 3))

    for i in range(0,(3 * self.sboxes),3):
      
      for j in range(3):
        a[j] = states[j][i + 2]
        b[j] = states[j][i + 1]
        c[j] = states[j][i]

      ab = self.mpc_and(a, b, tapes, r, t)
      bc = self.mpc_and(b, c, tapes, r, t)
      ca = self.mpc_and(c, a, tapes, r, t)

      for j in range(3):
        states[j][i + 2] = a[j] ^ bc[j]
        states[j][i + 1] = a[j] ^ b[j] ^ ca[j]
        states[j][i]     = a[j] ^ b[j] ^ c[j] ^ ab[j]

    return states

  # MPC LowMC AND for signing
  def mpc_and(self, in1, in2, tapes, r, t):
    
    rand = BitVector(intVal = 0, size = 3)
    rand[0] = tapes[0][self.__tapes_pos]
    rand[1] = tapes[1][self.__tapes_pos]
    rand[2] = tapes[2][self.__tapes_pos]

    result = BitVector(intVal = 0, size = 3)

    for i in range(3):
      result[i] = (in1[i] & in2[(i + 1) % 3]) ^ \
                  (in1[(i + 1) % 3] & in2[i]) ^ \
                  (in1[i] & in2[i]) ^ \
                  rand[i] ^ \
                  rand[(i + 1) % 3]      
      self.__views[t][i].transcript[self.__tapes_pos] = result[i]

    self.__tapes_pos += 1

    return result

  # MPC LowMC XOR a constant
  def mpc_xor_constant(self, ins, constant):

    ins[0] = ins[0] ^ constant
    return ins

  # MPC LowMC XOR outs and ins for three players
  def mpc_xor(self, outs, ins):

    for i in range(3):
      outs[i] = outs[i] ^ ins[i]
    return outs

  # Calculate the commitments by hashing the 
  # seeds and views for all three players
  def mpc_commit(self, t):

    for i in range(3):

      # H4(seed[mpc_round][player])
      shake128 = hashlib.shake_128()
      shake128.update(bytes([0x04]))
      shake128.update(bytes.fromhex(self.__seeds[t][i].get_bitvector_in_hex()))
      h4 = shake128.digest(int(self.hash_length / 8))

      # Calculate h0(h4, views[t])
      shake128 = hashlib.shake_128()
      shake128.update(bytes([0x00]))
      shake128.update(h4)
      shake128.update(bytes.fromhex(self.__views[t][i].i_share.get_bitvector_in_hex()))
      shake128.update(bytes.fromhex(self.__views[t][i].transcript.get_bitvector_in_hex()))
      shake128.update(bytes.fromhex(self.__views[t][i].o_share.get_bitvector_in_hex()))

      self.__commitments[t][i].hash = shake128.digest(int(self.hash_length / 8))
      
  ################################
  ###   Challenges and proofs  ###
  ################################

  # Calculating the challenges in {0,1,2}*
  def h3(self, message):

    shake128 = hashlib.shake_128()

    # Hash the output shares with prefix 0x01
    shake128.update(bytes([0x01]))    
    for t in range(self.mpc_rounds):
      for player in range(3):
         shake128.update(bytes.fromhex(self.__views[t][player].o_share.get_bitvector_in_hex()))
    
    # Hash the commitments
    for t in range(self.mpc_rounds):
      for player in range(3):
         shake128.update(self.__commitments[t][player].hash)
    
    # Hash the circuit output
    circuit_output = self.__views[0][0].o_share ^ \
                     self.__views[0][1].o_share ^ \
                     self.__views[0][2].o_share
    shake128.update(bytes.fromhex(circuit_output.get_bitvector_in_hex()))

    # Hash p (plaintext), salt, message
    shake128.update(bytes.fromhex(self.__pub_key.p.get_bitvector_in_hex()))
    shake128.update(bytes.fromhex(self.__salt.get_bitvector_in_hex()))
    shake128.update(message)

    tmp_hash = shake128.digest(int(self.hash_length / 8))

    tmp_bitvector = BitVector(rawbytes = tmp_hash)
    bit_pos = 0
    result = []
    while(1):
      a = tmp_bitvector[bit_pos]
      b = tmp_bitvector[bit_pos + 1]
      if (a == 0 and b == 0):
        result.append(0)
      if (a == 0 and b == 1):
        result.append(1)
      if (a == 1 and b == 0):
        result.append(2)
      bit_pos += 2
      if (len(result) >= self.mpc_rounds):
        break
      if (bit_pos >= self.hash_length):
        shake128 = hashlib.shake_128()
        shake128.update(bytes([0x01]))
        shake128.update(tmp_hash)
        tmp_hash = shake128.digest(int(self.hash_length / 8))
        tmp_bitvector = BitVector(rawbytes = tmp_hash)
        bit_pos = 0
  
    return result

  # Calculating the proofs from the challenges, seeds,
  # transcripts, i_shares and commitments
  def prove(self):

    proofs = []

    for t in range(self.mpc_rounds):
      tmp_proof = Proof()

      challenge = self.__challenges[t]
      if (challenge == 0):
        tmp_proof.seed_1 = self.__seeds[t][0]
        tmp_proof.seed_2 = self.__seeds[t][1]

      if (challenge == 1):
        tmp_proof.seed_1 = self.__seeds[t][1]
        tmp_proof.seed_2 = self.__seeds[t][2]
        tmp_proof.i_share = self.__views[t][2].i_share

      if (challenge == 2):
        tmp_proof.seed_1 = self.__seeds[t][2]
        tmp_proof.seed_2 = self.__seeds[t][0]
        tmp_proof.i_share = self.__views[t][2].i_share
      
      tmp_proof.transcript = self.__views[t][(challenge + 1) % 3].transcript
      tmp_proof.view_3_commit = self.__commitments[t][(challenge + 2) % 3].hash

      proofs.append(tmp_proof)

    return proofs    

  # Get one long hash for the random tapes
  def mpc_create_random_tape(self, mpc_round, player, length):

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
  
  ###########################
  ###   Helper functions  ###
  ###########################

  # Set or generate the priv and pub key
  def generate_keys(self, p = None, priv_key = None):

    # Generate random p (plaintext) with length self.keysize
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

  # Serialize a full signature from self.__signature
  def serialize_signature(self):

    result = bytearray()

    # Append challenges as bytes
    challenges = BitVector(size = 0)
    for i in self.__signature.challenges:
      if (i == 0):
        challenges = challenges + BitVector(bitlist = [0,0])
      if (i == 1):
        challenges = challenges + BitVector(bitlist = [1,0])
      if (i == 2):
        challenges = challenges + BitVector(bitlist = [0,1])
    diff = 8 - (challenges.length() % 8)
    challenges = challenges + BitVector(intVal = 0, size = diff)
    result.extend(bytes.fromhex(challenges.get_bitvector_in_hex()))

    # Append salt as bytes
    result.extend(bytes.fromhex(self.__signature.salt.get_bitvector_in_hex()))

    # Append all proofs
    for t in range(self.mpc_rounds):
      challenge_value = self.__signature.challenges[t]
      
      result.extend(self.__signature.proofs[t].view_3_commit)
      result.extend(bytes.fromhex(self.__signature.proofs[t].transcript.get_bitvector_in_hex()))
      result.extend(bytes.fromhex(self.__signature.proofs[t].seed_1.get_bitvector_in_hex()))
      result.extend(bytes.fromhex(self.__signature.proofs[t].seed_2.get_bitvector_in_hex()))
      if (challenge_value == 1 or challenge_value == 2):
        result.extend(bytes.fromhex(self.__signature.proofs[t].i_share.get_bitvector_in_hex()))

    print(result.hex())

  # Print out a (not serialized) signature from self.__signature
  def print_signature(self):

    print("Signature:")
    print("Salt: " + self.__salt.get_bitvector_in_hex())
    for t in range(self.mpc_rounds):
      print("Iteration t: " + str(t))
      print("e_" + str(t) + ": " + str(self.__signature.challenges[t]))
      print("b_" + str(t) + ": " + self.__signature.proofs[t].view_3_commit.hex())
      print("transcript: " + self.__signature.proofs[t].transcript.get_bitvector_in_hex())
      print("seed1: " + self.__signature.proofs[t].seed_1.get_bitvector_in_hex())
      print("seed2: " + self.__signature.proofs[t].seed_2.get_bitvector_in_hex())
      if (not (self.__signature.challenges[t] == 0)):
        print("inputShare: " + self.__signature.proofs[t].i_share.get_bitvector_in_hex())

  
def main():
  picnic = Picnic()
  priv_key = bytes([0xA5, 0x2A, 0x6C, 0x86, 0xC2, 0x9A, 0x19, 0x3B, 0x42, 0xE9, 0x97, 0xAC, 0xAC, 0xB2, 0x66, 0x03])  
  p        = bytes([0x95, 0xB3, 0xB0, 0x21, 0x8B, 0x6D, 0xFE, 0xEE, 0x04, 0x9D, 0xF0, 0x22, 0x6E, 0x5B, 0xB5, 0xEA])
  picnic.generate_keys(p = p, priv_key = priv_key)

  message = bytearray([0x01] * 500)
  picnic.sign(message)
  picnic.print_signature()
  picnic.serialize_signature()

if __name__ == '__main__':
    main()
