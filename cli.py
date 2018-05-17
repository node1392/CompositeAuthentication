import socket #Socket Stuff
import diffie #Key Exchange
import aes #AES Encryption Stuff
import hashlib #Hash Fun

debug = 0 #Debugging Flag (0 for no debugging - 1 for debugging)

sAuth = 0 #Authenticated Flag
keyJar = 0 #Storing current session key
container_prev = '' #Storing previous container for Crypto
message_prev = '' #Storing previous message
breakS = 0

#############################################################
                        #Config Stuff#
#############################################################
SERVER = "127.0.0.1"
PORT = 5000
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

#############################################################
                        #Client Init#
#############################################################
while(sAuth==0 or sAuth==1):
    #At initial connection with server
    if(sAuth==0):
        #Initialize client key system
        d1 = diffie.DiffieHellman()

        #Generate key for client
        d1_pubkey = d1.gen_public_key()

        #Send key to Server
        client.sendall(bytes(str(d1_pubkey),'UTF-8'))

        #Await key from Server
        d2_pubkey =  client.recv(1024)

        #Generate shared key
        d1_sharedkey = d1.gen_shared_key(int(d2_pubkey.decode()))

        #Encode to be consumed by AES
        d1_sharedkey = d1_sharedkey.encode('UTF-8')

        #Generate fresh frame token
        keyJar = hashlib.sha256(d1_sharedkey).digest()
        container_prev = d1_sharedkey
        message_prev = d1_sharedkey

        #Setting to Authenticated
        sAuth = 1

    #Making sure client is authenticated and token is not empty
    if(sAuth==1 and len(keyJar)!=1):

        #Create new container for Crypto parameters
        container_prev = hashlib.sha256()
        container_prev.update(message_prev)
        container_prev.update(keyJar)
        container_prev = container_prev.digest()

        #Generate fresh frame token
        keyJar = hashlib.sha256(container_prev).digest()

        #Collect message from client
        out_data = input("-> ").encode('utf-8')
        message_prev = out_data

        if out_data.decode('utf-8')=='exit':
            sAuth = 2

        #Encrypt message prior to transmission
        out_data = aes.encrypt(out_data.decode('utf-8'),keyJar)

        #Send encrypted message to Server
        client.sendall(out_data)

    #Don't know what would cause a client to get into this state, but good practice regardless
    #This section just jumps them back into sharing keys
    else:
        keyJar = 0
        sAuth = 0

#Terminate socket connection
client.close()
