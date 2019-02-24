from picnic import *

#################################
###  Testvector Picnic-L1-FS  ###
#################################

# Init picnic and set keys
picnic = Picnic()
priv_key = bytes([0xA5, 0x2A, 0x6C, 0x86, 0xC2, 0x9A, 0x19, 0x3B, 0x42, 0xE9, 0x97, 0xAC, 0xAC, 0xB2, 0x66, 0x03])  
p        = bytes([0x95, 0xB3, 0xB0, 0x21, 0x8B, 0x6D, 0xFE, 0xEE, 0x04, 0x9D, 0xF0, 0x22, 0x6E, 0x5B, 0xB5, 0xEA])
picnic.generate_keys(p = p, priv_key = priv_key)

# Create message and then sign it:
# --------------------------------
message = bytearray([0x01] * 500)
# picnic.sign(message)

# Print, serialize and save the signature:
# ----------------------------------------
# picnic.print_signature()
# picnic.serialize_signature()
# picnic.write_ser_sig_to_file('signature.txt')

# Read an write the ser sig again:
# --------------------------------
picnic.read_ser_sig_from_file('signature.txt')
picnic.deserialize_signature()
# picnic.serialize_signature()
# picnic.write_ser_sig_to_file('signature_2.txt')

picnic.verify(message)

# Print the serialized signature:
# -------------------------------
# picnic.print_signature_ser()

