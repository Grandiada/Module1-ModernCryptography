Your task is to detect the correct 128-bit symmetric key transmitted over a secure but unstable connection, use it to decrypt an AES-128 encrypted message, generate an asymmetric Elliptic Curve key-pair, and create a digital signature over the original decrypted plaintext message.

Expected Results:
Correct Symmetric key
Decrypted message
Asymmetric public key.
Digital signature.

A brief step by step explanation: what did you do to receieve 1&2 . 



Steps:
Identify the correct symmetric key:
Given three 128-bit keys in HEX and the SHA-256 hash of the correct key, find the key that matches the provided hash.
Symmetric keys. Here they are in HEX
68544020247570407220244063724074
54684020247570407220244063724074
54684020247570407220244063727440

SHA-256 hash of the correct key. Hash is below in HEX
f28fe539655fd6f7275a09b7c3508a3f81573fc42827ce34ddf1ec8d5c2421c3

Decrypt the AES-128 encrypted message:
Use the correct symmetric key to decrypt the given message in HEX, with AES configured in CBC mode and the provided initialization vector in HEX.
AES encrypted message: 876b4e970c3516f333bcf5f16d546a87aaeea5588ead29d213557efc1903997e
CBC initialization vector: 656e6372797074696f6e496e74566563


Generate an asymmetric Elliptic Curve key-pair:
Generate a key-pair using any Elliptic Curve parameters, either in node.js/java/etc or online.

Create a digital signature:
Using the asymmetric key-pair, generate a digital signature over the original decrypted plaintext message.