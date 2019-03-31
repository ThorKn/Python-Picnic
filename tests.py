'''
---------------------------------------------------
Picnic Tests in Python
Author: Thorsten Knoll
Date: March 2019

This file is part of the Python-Picnic 
implementation and is published under MIT Licence. 
See the LICENCE.md file.
---------------------------------------------------
'''

from picnic import *

#################################
###  Testvector Picnic-L1-FS  ###
#################################

# Init picnic and set keys
picnic = Picnic()
priv_key = bytes([0xA5, 0x2A, 0x6C, 0x86, 0xC2, 0x9A, 0x19, 0x3B, 0x42, 0xE9, 0x97, 0xAC, 0xAC, 0xB2, 0x66, 0x03])  
p        = bytes([0x95, 0xB3, 0xB0, 0x21, 0x8B, 0x6D, 0xFE, 0xEE, 0x04, 0x9D, 0xF0, 0x22, 0x6E, 0x5B, 0xB5, 0xEA])

# -------------------------------------
# Generate keys from testvectors above
# -------------------------------------
picnic.generate_keys(p = p, priv_key = priv_key)

# -------------------------------------
# Generate random keys
# -------------------------------------
# picnic.generate_keys()

# --------------------------------
# Create message and then sign it:
# --------------------------------
message = bytearray([0x01] * 500)
picnic.sign(message)

# ----------------------------------------
# Serialize and save the signature:
# ----------------------------------------
picnic.serialize_signature()
picnic.write_ser_sig_to_file('signature.txt')

# ---------------------------------
# Read an write the ser sig again.
# The two files then could be
# compared with "diff" to be equal.
# ---------------------------------
# picnic.read_ser_sig_from_file('signature.txt')
# picnic.deserialize_signature()
# picnic.serialize_signature()
# picnic.write_ser_sig_to_file('signature_2.txt')

# -----------------------------------------
# Read, deserialize and verify a signature
# -----------------------------------------
picnic.read_ser_sig_from_file('signature.txt')
picnic.deserialize_signature()
picnic.verify(message)

# --------------------------------
# Print the signatures in console:
# --------------------------------
# picnic.print_signature()
# picnic.print_signature_ser()


