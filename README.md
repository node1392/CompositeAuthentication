# CompositeAuthentication

CompAuth is a new authentication protocol designed to minimize the damage caused by session hijacking and to provide perfect forward secrecy in web applications. It does this by combining Diffie-Hellman key exchange with chained hashing to create an encryption key that changes with each transaction, thus ensuring perfect forward secrecy.

Our initial target for rollout of CompAuth is in the form of a Node.js Express app. Express is a framework for javascript based servers, and with our app any web developer writing an express app can import and use our app in their own projects. A more generic API may be developed in the future.

The first step of the CompAuth protocol is to agree on a starting value for the key. This is accomplished by performing a standard Diffie-Hellman key exchange between the two parties to generate a 256-bit shared secret. The initial exchange is signed using TLS certificates, to avoid a Man in the Middle attack. This secret will serve as the key used to initialize the session.

When one party sends a message to the other, they encrypt the message and send it (in our case we use 256 bit AES, but any encryption standard can be used). Signatures do not need to be used from this point onwards. After they have sent the message, they update their key by concatenating the plaintext message with the secret key and performing a secure hash on the resulting string (in our example, we used SHA-256). The result of this hash becomes the key for the next transmission. The recipient performs the same operation when they receive a message, first decrypting it to read the plaintext and hashing it with the key to generate a new key. In doing so, both the sender and recipient update their keys to stay in sync.

