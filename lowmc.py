'''
LowMC Blockcipher
Author: Thorsten Knoll
Date: Feb 2019
'''

import os
from BitVector import BitVector

class LowMC:

  def __init__(self):
    self.blocksize = 128
    self.keysize = 128
    self.number_sboxes = 10
    self.number_rounds = 20
    self.lin_layer = []
    self.round_consts = []
    self.round_key_mats = []
    self.__priv_key = None
    self.plaintext = None
    self.__state = None
    self.__sbox = [ 0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02 ]
    self.__sbox_inv = [ 0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04 ]
  
    self.__read_constants()

    '''
    self.generate_priv_key()
    '''

  def generate_priv_key(self):
    temp_key = os.urandom(self.keysize / 8)
    self.__priv_key = BitVector(rawbytes = temp_key)

  def set_priv_key(self, priv_key):
    self.__priv_key = BitVector(rawbytes = priv_key)

  # Encrypts a plaintext
  # @param plaintext must be python bytes, length blocksize
  # @return ciphertext as python bytes, length blocksize
  def encrypt(self, plaintext):
    assert (len(plaintext) * 8) == self.blocksize, "Plaintext has length != blocksize"
    self.__state = BitVector(rawbytes = plaintext)

    self.__key_addition(0)

    for i in range(self.number_rounds):
      self.__apply_sbox()
      self.__multiply_with_lin_mat(i)
      self.__state = self.__state ^ self.round_consts[i]
      self.__key_addition(i + 1)

    result = bytes.fromhex(self.__state.get_bitvector_in_hex())
    self.__state = None
    return result

  def decrypt(self, ciphertext):
    result = cipertext
    return result

  def __apply_sbox(self):
    result = BitVector(size = self.blocksize)
    state_copy = self.__state.deep_copy()

    # Copy the identity part of the message
    result_ident = state_copy[(3 * self.number_sboxes):self.blocksize]

    # Substitute the rest of the message with the sboxes
    # ----------------------------------------------------
    # ATTENTION: The 3-bit chunks seem to be reversed 
    # in the Picnic-Ref-Implementation, compared to the
    # LowMC-Ref-Implementation and the original LowMC-paper.
    # Example: state[0:3]='001' becomes '100' then gets sboxed 
    # to '111' and reversed again for the state-update.
    # ----------------------------------------------------
    state_copy = self.__state[0:(3 * self.number_sboxes)]
    result_sbox = BitVector(size = 0)
    for i in range(self.number_sboxes):
      state_index = (3 * i)
      state_3_bits = state_copy[state_index:state_index + 3].reverse()
      sbox_3_bits = BitVector(intVal = self.__sbox[int(state_3_bits)], size = 3).reverse()
      result_sbox = result_sbox + sbox_3_bits

    result = result_sbox + result_ident
    self.__state = result
    

  def __multiply_with_lin_mat(self, r):
    result = BitVector(size = self.blocksize)
    for i in range(self.blocksize):
      result[i] = (self.lin_layer[r][i] & self.__state).count_bits() % 2
    self.__state = result
    
  def __key_addition(self, r):
    round_key = BitVector(size = self.keysize)
    for i in range(self.blocksize):
      round_key[i] = (self.round_key_mats[r][i] & self.__priv_key).count_bits() % 2
    self.__state = self.__state ^ round_key

  def __read_constants(self):
    with open('lowmc_picnic1_l1.dat', 'r') as matfile:
      const_data = matfile.read()

    const_data_split = const_data.split('\n')

    # Check for correct parameters and file length
    params = const_data_split[0:3]
    assert params[0] == str(self.blocksize), "Wrong blocksize in data file!"
    assert params[1] == str(self.keysize), "Wrong keysize in data file!"
    assert params[2] == str(self.number_rounds), "Wrong number of rounds in data file!"
    assert (len(const_data_split) - 1) == \
    3 + (((self.number_rounds * 2) + 1) * self.blocksize) + self.number_rounds,\
    "Wrong file size (number of lines)" 

    # Linear layer matrices
    lines_offset = 3
    lines_count = self.number_rounds * self.blocksize
    lin_layer = const_data_split[lines_offset:(lines_offset + lines_count)]
    for r in range(self.number_rounds):
      mat = []
      for s in range(self.blocksize):
        mat.append(BitVector(bitlist = eval(lin_layer[(r * self.blocksize) + s])))
      self.lin_layer.append(mat)

    # Round constants
    lines_offset += lines_count 
    lines_count = self.number_rounds
    round_consts = const_data_split[lines_offset:(lines_offset + lines_count)]
    for line in round_consts:
      self.round_consts.append(BitVector(bitlist = eval(line)))    

    # Round key matrices
    lines_offset += lines_count
    lines_count = (self.number_rounds + 1) * self.blocksize
    round_key_mats = const_data_split[lines_offset:(lines_offset + lines_count)]
    for r in range(self.number_rounds + 1):
      mat = []
      for s in range(self.blocksize):
        mat.append(BitVector(bitlist = eval(round_key_mats[(r * self.blocksize) + s])))
      self.round_key_mats.append(mat)

def main():

  lowmc = LowMC()

  # Testvectors for Picnic1_L1
  test_priv_key = bytes([ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  test_plaintext = bytes([ 0xAB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  test_ciphertext = bytes([ 0x0E, 0x30, 0x72, 0x0B, 0x9F, 0x64, 0xD5, 0xC2, 0xA7, 0x77, 0x1C, 0x8C, 0x23, 0x8D, 0x8F, 0x70 ])

  lowmc.set_priv_key(test_priv_key)
  cipher = lowmc.encrypt(test_plaintext)
  print("plaintext:           " + test_plaintext.hex().upper())
  print("ciphertext:          " + cipher.hex().upper())
  print("expected ciphertext: " + test_ciphertext.hex().upper())

if __name__ == '__main__':
    main()

