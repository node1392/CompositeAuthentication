import socket #Socket Stuff
import threading #Thread Stuff
import diffie #Key Exchange
import aes #AES Encryption Stuff
import hashlib #Hash Fun

debug = 0 #Debugging Flag (0 for no debugging - 1 for debugging)
currentClient = 0

#############################################################
                        #Server Class#
#############################################################
class ClientThread(threading.Thread):
    def __init__(self,clientAddress,clientsocket):
        threading.Thread.__init__(self)

        #Create child socket for threaded client
        self.addr = clientAddress
        self.csocket = clientsocket
        global currentClient
        currentClient+=1
        self.num = currentClient
        print ("New connection added: ", clientAddress)

    def run(self):
        print ("Connection from : ", clientAddress)

        self.sAuth = 0 #Successfully shared keys secretly
        self.message_prev = '' #Message Store
        self.msg = '' #Default message
        self.keyJar = 0 #Contains the current session key
        self.container_prev = '' #Contains the previous container for Crypto

        while True:
            if(self.sAuth == 0):
                #Wait for client to connect/send data
                data = self.csocket.recv(2048)

                #Decrypt client's key
                d1_pubkey = data.decode()
                if(debug == 1): print("Received Client Key")

                #Initialize server key system
                d2 = diffie.DiffieHellman()

                #Generate key for server
                d2_pubkey = d2.gen_public_key()
                if(debug == 1): print("Generated Server Key")

                #send key to client
                self.csocket.send(bytes(str(d2_pubkey),'UTF-8'))

                #Derive shared key
                d2_sharedkey = d2.gen_shared_key(int(d1_pubkey))

                #Encoding to be consumed by AES
                d2_sharedkey = d2_sharedkey.encode('UTF-8')
                if(debug == 1): print("Server: Shared Key Derived: ", d2_sharedkey)

                #Set initial token
                self.keyJar = hashlib.sha256(d2_sharedkey).digest()
                self.container_prev = d2_sharedkey
                self.message_prev = d2_sharedkey
                if(debug == 1): print("Server: Fresh seed created to be used for subsequent communications")

                #Set client to authenticated
                self.sAuth = 1

            #Making sure client is authenticated and token is not empty
            if(self.sAuth == 1 and len(self.keyJar)!=1):

                #Waiting for message from authenticated client
                data = self.csocket.recv(2048)

                #Create new container for Crypto parameters
                container_prev = hashlib.sha256()
                container_prev.update(self.message_prev)
                container_prev.update(self.keyJar)
                container_prev = container_prev.digest()

                #Generate session key for new frame
                self.keyJar = hashlib.sha256(container_prev).digest()
                if(debug == 1): print("New key generated for new message: ",self.keyJar)

                #Decrypt the message sent by the client
                self.msg = aes.decrypt(data,self.keyJar).decode()
                self.message_prev = self.msg.encode('utf-8')
                print ("Message Decrypted From client ",self.num,": ", self.msg)

                #If exit, break session with client
                if self.msg=='exit':
                    break
                self.msg = self.msg.encode("utf-8")
                self.csocket.send(self.msg)

            else: #Don't know what would cause a client to get into this state, but good practice regardless
                #This section just jumps them back into sharing keys
                self.keyJar = 0
                self.sAuth = 0

        print ("Client at ", clientAddress , " disconnected...") #Client has disconnected

#############################################################
                        #Config Stuff#
#############################################################
LOCALHOST = "127.0.0.1"
PORT = 5000

#############################################################
                        #Server Init#
#############################################################
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((LOCALHOST, PORT))
print("Server starting")
debugFlag = input("Would you like to enable debugging? (Y or N):\n->")
if(str(debugFlag).lower()[0] == 'y'):
    print("Debugging enabled, now serving")
    debug = 1
else:
    print("Debugging disabled, now serving")
    debug = 0
print("Waiting for client request..")
while True:
    server.listen(1)
    clientsock, clientAddress = server.accept()
    newthread = ClientThread(clientAddress, clientsock)
    newthread.start()
