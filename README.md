# CompositeAuthentication

CompAuth is a new authentication protocol designed to minimize the damage caused by session hijacking and to provide perfect forward secrecy in web applications. It does this by combining Diffie-Hellman key exchange with chained hashing to create an encryption key that changes with each transaction, thus ensuring perfect forward secrecy.
Our initial target for rollout of CompAuth is in the form of a Node.js Express app. Express is a framework for javascript based servers, and with our app any web developer writing an express app can import and use our app in their own projects. A more generic API may be developed in the future.
