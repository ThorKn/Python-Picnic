'''
---------------------------------------------------
Picnic typeclasses in Python
Author: Thorsten Knoll
Date: March 2019

This file is part of the Python-Picnic 
implementation and is published under MIT Licence. 
See the LICENCE.md file.
---------------------------------------------------
'''

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
    self.hash = BitVector(intVal = 0, size = hash_length)
    self.n_commitments = n_commitments

class Proof:
  def __init__(self):
    self.seed_1 = None
    self.seed_2 = None
    self.i_share = None
    self.transcript = None
    self.view_3_commit = None

class Signature:
  def __init__(self):
    self.proofs = None
    self.challenges = None
    self.salt = None

