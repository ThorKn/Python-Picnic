# Python-Picnic
## Description
Python-Picnic is a Python reimplementation of the Picnic signaturescheme. Python-Picnic exists because i want to understand and learn the Picnic algorithm.    
## References
The Picnic reference implementation is in C under MIT license and can be found here:

[Picnic Github](https://github.com/Microsoft/Picnic)

The Picnic paper is available at:

[Picnic paper](https://microsoft.github.io/Picnic/)
## Disclaimer
This implementation is for the sole purpose of learning and understanding the Picnic algorithm. It's not recommended to use this code in productive environment. Additionaly this code is very slow, compared to the reference implementation (in C++). 
## Prerequisites
* Python >=3.6
* hashlib including SHA3-SHAKE is needed (incl. in Python >=3.6)
* Additional package: BitVector

It's recommended to use a Python virtual environment like ```virtualenv```. The BitVector package can be installed with 
``` 
pip install BitVector 
```
## Documentation
This repository contains a description of the implementation as PDF in the /docs folder.
## Tests
To run the tests with a testvector, simply execute
```
tests.py
```
This file is also a good starting point to see the usage of the Python-Picnic functions.
