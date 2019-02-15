# Python-Picnic
Picnic: Post-quantum signatures in Python
### Prerequisites
* Python 3
* Package BitVectors
### Run
So far only the LowMC blockcipher with parameters for Picnic-L1 is implemented.

The generator creates the constants for LowMC with
* blocksize = 128 bit
* keysize = 128 bit
* sboxes = 10
* rounds = 20

Run the generator.py to create the file lowmc_picnic1_l1.dat. Afterwards running lowmc.py does a single encryption of the first testvector from the Picnic reference implementation.
