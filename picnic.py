import os
from BitVector import BitVector
from lowmc import LowMC

class Picnic:

  def __init__(self):
    self.blocksize = 128
    self.keysize = 128
    self.number_rounds = 20
    self.number_sboxes = 10
    self.lowmc = LowMC('picnic-L1')

    self.__priv_key = None
    self.__pub_key = None  

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
    self.__pub_key = [bitvector_c, bitvector_p]

    print("pub key:")
    print(raw_c.hex().upper())
    
def main():
  picnic = Picnic()
  priv_key = bytes([0xA5, 0x2A, 0x6C, 0x86, 0xC2, 0x9A, 0x19, 0x3B, 0x42, 0xE9, 0x97, 0xAC, 0xAC, 0xB2, 0x66, 0x03])  
  p        = bytes([0x95, 0xB3, 0xB0, 0x21, 0x8B, 0x6D, 0xFE, 0xEE, 0x04, 0x9D, 0xF0, 0x22, 0x6E, 0x5B, 0xB5, 0xEA])
  picnic.generate_keys(p = p, priv_key = priv_key)


if __name__ == '__main__':
    main()
