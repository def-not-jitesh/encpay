# encpay
Tool for encrypting/obfuscating shellcode.

encpay is a command-line tool using which shellcode generated by msfvenom can be encrypted/obfuscated.
encpay supports xor, rc4 algorithms for encryption and ipv4, ipv6 obfuscation methods for obfuscation.

#### HOW IT WORKS ####

encpay expects two flags, -f and -m

the -f flag represents the .bin file which contains the shellcode generated by msfvenom.
the -m flag represents the method of encryption/obfuscation to perform on the shellcode.

the program returns the obfuscated payload in a .bin file for obfuscation methods.
the program returns decryption function and key in a .c file for encryption methods.

#### HOW TO INSTALL ####

to compile the program you would need the minGW x86-64 compiler.

clone this repository and run the following commands to compile the program. 
 `$: make`

