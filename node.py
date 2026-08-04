# basic sockets
import socket
from threading import Thread
import threading

# basic encryption (dh + aes)
from Cryptodome.Util.number import getPrime # python3.11 -m pip install pycryptodomex
from Cryptodome import Random
from Cryptodome.Cipher import AES

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

import secrets
import base64
import hashlib

# database and authentication
from bs4 import BeautifulSoup # pip install beautifulsoup4
#from getmac import get_mac_address as gma
from argon2 import PasswordHasher # pip install argon2-cffi
from argon2.exceptions import VerifyMismatchError
import json

# gui
import tkinter as tk
from tkinter import messagebox

####################
## CRYPTOGRAPHY
####################

# aes gcm encryption class
class GCM:
    def __init__(self, secretKey):
        self.secretKey = secretKey

    def encrypt(self, msg):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None)
        aesKey = hkdf.derive(self.secretKey)
                       
        cipher = AES.new(aesKey, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
        return cipher.nonce + ciphertext + tag

    def decrypt(self, msg):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None)
        aesKey = hkdf.derive(self.secretKey)
                       
        nonce = msg[:16]
        tag = msg[-16:]
        msg = msg[16:-16]

        cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
        try:
            return cipher.decrypt_and_verify(msg, tag).decode()
        except ValueError:
            print("Decryption failed: Key incorrect or message tampered with")
            return False

# verify login password using argon 2 hash
def verify_password(hashed, password):
    try:
        PasswordHasher().verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False

####################
## AUTHENTICATION
####################

# load local ssh public and private keys
# generated with 'ssh-keygen -t ed25519'
with open('key.pub', 'rb') as key_file:
    public_key_bytes = key_file.read()

self_authentication_public_key_string = public_key_bytes.decode()
self_authentication_public_key = serialization.load_ssh_public_key(public_key_bytes)
self_hostname = socket.gethostname()

print("WELCOME TO P2P LAN")
print("Your username is:", self_hostname)
print("You can change this by changing your hostname.")

# authenticate user by asking for password to decrypt private key
while True:
    print()
    password = input("Enter your SSH key password: ").encode()
    try:
        with open('key', 'rb') as key_file:
            self_authentication_private_key = serialization.load_ssh_private_key(key_file.read(), password=password)
        break
    except Exception as e:
        print("ERROR. PLEASE TRY AGAIN.")
        print(e)

# sign challenge
def sign(message):
    return self_authentication_private_key.sign(message)

def verify(public_key, signature, message):
    # parse it
    if type(public_key) == str:
        public_key = serialization.load_ssh_public_key(public_key.encode("utf-8"))

    # verify signature
    try:
        public_key.verify(signature, message)
        return True
    except:
        return False

####################
## SOCKETS
####################
   
# send message + byte size
def sendall(this_socket, content):
    print("---Sending Information---")
    byte_size = str(len(content))
    msg = byte_size + ' '

    print(msg, content)
    this_socket.sendall(msg.encode() + content)

# receive all (no matter byte size)
def recvall(this_socket, chunk_size=1024):
    print("---Waiting for Message---")
    first_chunk = this_socket.recv(chunk_size)
    # connection terminated
    if not first_chunk:
        return False

    space_enc = ' '.encode()
    splitted = first_chunk.split(space_enc)
    byte_size = splitted[0]
    everything_else = space_enc.join(splitted[1:])

    if len(everything_else) == int(byte_size):
        return everything_else
    else:
        all_chunks = everything_else
        byte_size -= chunk_size
        while byte_size > 0:
            next_chunk = this_socket.recv(chunk_size)
            # connection terminated
            if not next_chunk:
                return False
            all_chunks += next_chunk
            byte_size -= chunk_size

        return all_chunks

####################
## LISTENER
####################

# list of all server sockets
list_lock_all_servers = threading.Lock()
dict_lock_servers = threading.Lock()
dict_lock_ciphers = threading.Lock()
dict_lock_initiated_widgets = threading.Lock()
dict_lock_untrusted_widgets = threading.Lock()

all_servers = []
servers = dict()
ciphers = dict()
initiated_widgets = dict()
untrusted_widgets = dict()

# process for each client
def clientHandler(communication_socket, address):
    global untrusted_list
    try:
        print('CLIENT HANDLER CREATED FOR ADDRESS', address)

        # wait for client message and close socket if connection terminated
        def get_message():
            content = recvall(communication_socket)
            # connection terminated
            if not content:
                print("CONNECTION CLOSED")
                communication_socket.close()
                return False
            else:
                print('---Message Received from client at', address, '!---')
                print(content)
                return content

        # dh initialisation
        P = getPrime(2048)                     # 2048 bit prime for security
        G = 5                                  # generator doesn't have to be large
        dh_private_key = secrets.randbelow(2**512) # private key should be at least 256 bits

        # identify addresses
        address, _ = address

        authenticated_self = False
        authenticated_client = False
        client_authentication_public_key = None
        challenge = None
        # authentication challenges
        print('---AUTHENTICATION FOR CLIENT', address, '---')
        while not (authenticated_self and authenticated_client):
            # take in new messages
            message = get_message()
            if not message: return

            # split into command and content
            splitted = message.split(b':::')

            if len(splitted) > 0:
                command = splitted[0]
                content = b':::'.join(splitted[1:])

                # challenges
                if command == b'sign':
                    signature = sign(content)
                    sendall(communication_socket, signature)
                elif command == b'valid':
                    authenticated_self = True
                    sendall(communication_socket, 'okay'.encode())
                elif command == b'hello':
                    client_authentication_public_key = content.decode()
                    challenge = secrets.token_bytes(32)
                    sendall(communication_socket, challenge)
                elif command == b'invalid':
                    # exit if authentication fails
                    return
                elif command == b'signed':
                    # ensure we have their public key
                    if client_authentication_public_key == None:
                        challenge = secrets.token_bytes(32)
                        sendall(communication_socket, challenge)
                    else:
                        # verify signature and exit if invalid
                        signature = content
                        if verify(client_authentication_public_key, signature, challenge):
                            sendall(communication_socket, 'valid'.encode())
                            authenticated_client = True
                        else:
                            sendall(communication_socket, 'invalid'.encode())
                            return
       
        # authentication complete. create bidirectional connection
        with list_lock_all_servers:
            print(servers)
            if address not in all_servers:
                with dict_lock_untrusted_widgets:
                    text = address + ' (' + parse_user_key(client_authentication_public_key) + ')'
                    widget = tk.Label(untrusted_list, text=text, wraplength=180, bg='yellow')
                    widget.grid(padx=10, pady=10)
                    untrusted_widgets[address] = widget
                server = threading.Thread(target=create_sender, args=(address, client_authentication_public_key, widget, False))
                server.start()
                all_servers.append(address)

        encrypted = False
        # dh key exchange
        print('---DH KEY EXCHANGE FOR CLIENT', address, '---')
        while not encrypted:
            # take in new messages
            message = get_message()
            if not message: return

            # split into command and content
            splitted = message.split(b':::')

            if len(splitted) > 0:
                command = splitted[0]
                content = b':::'.join(splitted[1:])

                # dh exchanges
                if command == b'prime':
                    sendall(communication_socket, str(P).encode())
                elif command == b'generator':
                    sendall(communication_socket, str(G).encode())
                elif command == b'exchange':
                    try:
                        clientKey = int(content.decode())
                        serverKey = pow(G, dh_private_key, P)
                        secretKey = pow(clientKey, dh_private_key, P)

                        byteKey = secretKey.to_bytes((secretKey.bit_length() + 7)//8, byteorder='big')
                        encrypted = byteKey
                       
                        sendall(communication_socket, str(serverKey).encode())
                    except:
                        sendall(communication_socket, 'invalid'.encode())

        # initialise AES cipher
        cipher = GCM(encrypted)

        print('---MAINTAING CONNECTION FOR CLIENT', address, '---')

        while True:
            # take in new messages
            message = get_message()
            if not message: return

            # split into command and content
            splitted = message.split(b':::')

            if len(splitted) > 0:
                command = splitted[0]
                content = b':::'.join(splitted[1:])

                # add message
                if command in [b'general', b'spam', b'casual']:
                    # msg = channel.get().encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(text) + ':::'.encode()
                    # sendall(client_socket, msg + sign(text.encode()))
                    sender_public_key = cipher.decrypt(content.split(b':::')[0])
                    signature = content.split(b':::')[-1]
                    content = cipher.decrypt(b':::'.join(content.split(b':::')[1:-1]))
                    
                    print("Content:", content, "\nSender Public Key", sender_public_key)

                    if verify(sender_public_key, signature, content.encode()):
                        add_message(sender_public_key, content, command.decode())
                        show_messages()

                        ## TODO - resend (gossip protocol) and discard duplicate messages
                    else:
                        print("SIGNATURE INVALID")

    except Exception as e:
        print('---ERROR ERROR FOR CLIENT', address, '---')
        print(e)

    finally:
        print('---CLOSING CONNECTION TO CLIENT', address, '---')
        communication_socket.close()
        print(all_servers, servers)
        with dict_lock_servers:
            if address in servers.keys():
                servers[address].close()
                del servers[address]
        with list_lock_all_servers:
            if address in all_servers:
                all_servers.remove(address)
        with dict_lock_ciphers:
            if address in ciphers.keys():
                del ciphers[address]

        with dict_lock_untrusted_widgets:
            if address in untrusted_widgets:
                untrusted_widgets[address].config(bg='red')
        with dict_lock_initiated_widgets:
            if address in initiated_widgets:
                initiated_widgets[address].config(bg='red')
        print(all_servers, servers)

# listen for clients
def listen():
    print('LISTENING...')

    # set up server
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    listener.bind(('0.0.0.0', 65432))
    listener.listen(5)

    print("Server set up :D")
   
    while True:
        communication_socket, address = listener.accept()

        print("CONNECTION DETECTED FROM:", address)

        # make new thread for each client
        client = threading.Thread(target=clientHandler, args=(communication_socket, address,))
        client.start()
       
####################
## SENDER
####################

# sending socket
def spawn_senders():
    global trusted_list

    data = read_connections()

    print('SPAWNING SENDERS TO:')
    for address, key in data.items():
        print('ADDRESS:', address)
        add_sender(address, key, True)

def add_sender(address, key, trusted):
    with list_lock_all_servers:
        print(servers)
        if address not in all_servers:
            with dict_lock_initiated_widgets:
                text = address + ' (' + parse_user_key(key) + ')'
                widget = tk.Label(trusted_list, text=text, wraplength=180, bg='yellow')
                widget.grid(padx=10, pady=10)
                reset = tk.Button(trusted_list, text='R', command=lambda: add_sender(address, key, widget, trusted))
                reset.grid(padx=10, pady=10)
                initiated_widgets[address] = widget
            server = threading.Thread(target=create_sender, args=(address, key, widget, trusted))
            server.start()
            all_servers.append(address)

def create_sender(address, server_public_key, widget, trusted):
    try:
        print('CREATING SENDER FOR', address)

        # server parameters
        server = (address, 65432)

        # dh private key
        dh_private_key = secrets.randbelow(2**256)
   
        # connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(server)

        # authenticate server
        print('---AUTHENTICATING WITH SERVER', address, '---')
        hello = 'hello:::' + self_authentication_public_key_string
        sendall(client_socket, hello.encode())

        challenge = recvall(client_socket)
        signature_msg = 'signed:::'.encode() + sign(challenge)
        sendall(client_socket, signature_msg)

        response = recvall(client_socket).decode()
        if response == 'invalid': return
        challenge = secrets.token_bytes(32)
        challenge_msg = 'sign:::'.encode() + challenge
        sendall(client_socket, challenge_msg)

        signature = recvall(client_socket)
        if verify(server_public_key, signature, challenge) == False:
            sendall(client_socket, 'invalid'.encode())
            return
        sendall(client_socket, 'valid'.encode())
        okay = recvall(client_socket)
        print(okay)

        # encrypt connection: diffie hellman
        print('---DH HANDSHAKE WITH SERVER', address, '---')
        # get prime
        sendall(client_socket, 'prime'.encode())
        P = int(recvall(client_socket).decode())

        # get generator
        sendall(client_socket, 'generator'.encode())
        G = int(recvall(client_socket).decode())

        clientKey = pow(G, dh_private_key, P) # modular exponentiation is more efficient. Before, it took forever.

        # exchange keys
        msg = "exchange:::" + str(clientKey)
        sendall(client_socket, msg.encode())
        key = int(recvall(client_socket).decode())

        # calculate secret key
        secretKey = pow(key, dh_private_key, P)

        # key generated might not be 256 bits. use a KDF to make it 256 bits.
        byteKey = secretKey.to_bytes((secretKey.bit_length() + 7)//8, byteorder='big')
        cipher = GCM(byteKey)

        print('---COMPLETED HANDSHAKE WITH SERVER', address, '---')
        print(servers)
        with dict_lock_servers:
            servers[address] = client_socket
        with dict_lock_ciphers:
            ciphers[address] = byteKey
        if trusted:
            with dict_lock_initiated_widgets:
                if address in initiated_widgets:
                    initiated_widgets[address].config(bg='green')
        else:
            with dict_lock_untrusted_widgets:
                if address in untrusted_widgets:
                    untrusted_widgets[address].config(bg='green')
        print(servers)

    except Exception as e:
        print('---ERROR ERROR FOR SENDER TO', address, '---')
        print(e)

        print('---CLOSING CONNECTION TO SERVER', address, '---')
        print(all_servers, servers)
        with dict_lock_servers:
            if address in servers.keys():
                del servers[address]
        with list_lock_all_servers:
            all_servers.remove(address)
        with dict_lock_ciphers:
            if address in ciphers.keys():
                del ciphers[address]

        if trusted:
            with dict_lock_initiated_widgets:
                if address in initiated_widgets:
                    initiated_widgets[address].config(bg='red')
        else:
            with dict_lock_untrusted_widgets:
                if address in untrusted_widgets:
                    untrusted_widgets[address].config(bg='red')
        print(all_servers, servers)
        client_socket.close()

####################
## DATABASE
####################

# thread safety
file_lock_messages = threading.Lock() # for messages
file_lock_connections = threading.Lock() # for connections

# reads the connections.xml file
# <connections><connection><address>...</address> <key>...</key></connection>... </connections>
def read_connections():
    # thread safety
    with file_lock_connections:
        with open('connections.xml') as f:
            data = f.read()
    
        Bs_data = BeautifulSoup(data, "xml")
        b_connections = Bs_data.find_all("connections")
    
        try:
            data = {connection.find_all("address")[0].text: connection.find_all("key")[0].text for connection in b_connections}
        except:
            data = dict()
       
    return data

# add an entry into connections.xml
def add_connection(address, key):
    with file_lock_connections:
        with open('connections.xml', 'r') as f:
            bs = BeautifulSoup(f, 'xml')

    # add data
    address_tag = bs.new_tag("address")
    address_tag.string = address

    key_tag = bs.new_tag("key")
    key_tag.string = key

    # add subtags to msg tag
    con_tag = bs.new_tag("connection")
    con_tag.append(address_tag)
    con_tag.append(key_tag)

    # add con tag to file
    connections = bs.find("connections")
    connections.append(con_tag)

    with file_lock_connections:
        with open('connections.xml', 'w') as f:
            f.write(str(bs))

# reads the messages.xml file
# <messages><message><text>...</text> <user>...</user> <channel>...</channel></message>... </messages>
def read_messages():
    # thread safety
    with file_lock_messages:
        with open('messages.xml') as f:
            data = f.read()

        Bs_data = BeautifulSoup(data, "xml")
        b_message = Bs_data.find_all("message")
     
        data = [{
                'text': msg.find('text').text,
                'user': msg.find('user').text,
                'channel': msg.find('channel').text
            } for msg in b_message]
       
    return data

# get hostname (username) from user's public key
# ssh-rsa ACTUAL_KEY user@hostname
def parse_user_key(user):
    username = user.split(' ')[-1]
    user_hostname = username.split('@')[-1].strip()
    return user_hostname

# add an entry into messages.xml
def add_message(user, text, channel):
    with file_lock_messages:
        with open('messages.xml', 'r') as f:
            bs = BeautifulSoup(f, 'xml')

    # add data
    user_tag = bs.new_tag("user")
    user_tag.string = user

    text_tag = bs.new_tag("text")
    text_tag.string = text

    channel_tag = bs.new_tag("channel")
    channel_tag.string = channel

    # add subtags to msg tag
    msg_tag = bs.new_tag("message")
    msg_tag.append(user_tag)
    msg_tag.append(text_tag)
    msg_tag.append(channel_tag)

    # add msg tag to file
    messages = bs.find("messages")
    messages.append(msg_tag)

    ## TODO - add xml data encryption

    with file_lock_messages:
        with open('messages.xml', 'w') as f:
            f.write(str(bs))

####################
## MESSAGE HANDLING
####################

# show all messages in listbox
def show_messages(event=None):
    global messages_list
    
    # database elements
    data = read_messages()

    # add database elements to gui
    messages_list.config(state=tk.NORMAL)
    messages_list.delete("1.0", tk.END)
    for each in data:
        # ensure message is in the correct channel
        if each['channel'] == channel.get():
            display = f"{parse_user_key(each['user'])}: {each['text']}\n"
            messages_list.insert(tk.END, display)
    messages_list.config(state=tk.DISABLED) 

# update gui of messages
def update_listbox(display):
    global messages_list

    messages_list.config(state=tk.NORMAL) 
    messages_list.insert(tk.END, display)
    messages_list.config(state=tk.DISABLED) 

# add a message to the database from server directly
def send_message():
    global clients

    # thread safety
    text = send_text.get("1.0", "end-1c")

    with file_lock_messages:
        with open('messages.xml') as f:
            data = f.read()

        bs = BeautifulSoup(data, "xml")
       
        # add data
        text_tag = bs.new_tag("text")
        text_tag.string = text

        user_tag = bs.new_tag("user")
        user_tag.string = self_authentication_public_key_string

        channel_tag = bs.new_tag("channel")
        channel_tag.string = channel.get()

        # add subtags to message tag
        message_tag = bs.new_tag("message")
        message_tag.append(text_tag)
        message_tag.append(user_tag)
        message_tag.append(channel_tag)

        # add message tag to file
        messages = bs.find("messages")
        messages.append(message_tag)
                                   
        with open('messages.xml', 'w') as f:
            f.write(str(bs))

    display = self_hostname + ': ' + text + '\n'

    print('---SENDING MESSAGE TO ALL SERVERS---')
    with dict_lock_servers:
        for address, client_socket in servers.items():
            print('ADDRESS:', address)

            # encrypt and sign message
            byteKey = ciphers[address]
            cipher = GCM(byteKey)

            msg = channel.get().encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(text) + ':::'.encode()
            sendall(client_socket, msg + sign(text.encode()))
   
    update_listbox(display)

    messagebox.showinfo("Message sent!", "Your message has been sent.")

####################
## CONNECTION HANDLING
####################

####################
## GUI
####################

def clear_frame(frame):
    # Iterate through all direct children of the frame and destroy them
    for widget in frame.winfo_children():
        widget.destroy()

# tk initialise
root = tk.Tk()
root.geometry('550x600')
root.title('P2P LAN')

# FRAME ONE - messages and chat
frame1 = tk.Frame(root)
frame1.grid(padx=10, pady=10)

tk.Label(frame1, text='P2P LAN App', font=("Arial", 25)).grid(row=0, column=0, columnspan=2)

chat = tk.Frame(frame1, height=200, width=250)
chat.grid(row=1, column=0, columnspan=1)
chat.grid_propagate(0)

messages = tk.Frame(frame1, height=200, width=250)
messages.grid(row=1, column=1, columnspan=1)
messages.grid_propagate(0)

frame1.rowconfigure(0, weight=1)
frame1.rowconfigure(1, weight=1)

channel = tk.StringVar(root)
channel.set("general")

options = ["general", "spam", "casual"]

send_text = tk.Text(chat, width=25, height=10)
send_text.grid(row=0, column=0, columnspan=2)

send_but = tk.Button(chat, text='Send', command=send_message)
send_but.grid(row=1, column=0, columnspan=1)

channel_menu = tk.OptionMenu(chat, channel, *options, command=show_messages)
channel_menu.grid(row=1, column=1, columnspan=1)

messages_list = tk.Text(messages, wrap='word')
messages_list.place(x=0, y=0, height=200, width=250)

show_messages()

# FRAME TWO - CONNECTIONS MANAGER
frame2 = tk.Frame(root)
frame2.grid(padx=10, pady=10)

tk.Label(frame2, text='Manage Connections', font=("Arial", 25)).grid(row=0, column=0, columnspan=2)

trusted = tk.Frame(frame2, height=300, width=250)
trusted.grid(row=1, column=0, columnspan=1)
trusted.grid_propagate(0)

tk.Label(trusted, text='TRUSTED').grid(row=0, column=0)

trusted_list = tk.Frame(trusted, height=200, width=200)
trusted_list.grid(row=1, column=0, columnspan=1)
trusted_list.grid_propagate(0)

untrusted = tk.Frame(frame2, height=300, width=250)
untrusted.grid(row=1, column=1, columnspan=1)
untrusted.grid_propagate(0)

tk.Label(untrusted, text='UNTRUSTED').grid(row=0, column=0)

untrusted_list = tk.Frame(untrusted, height=200, width=200)
untrusted_list.grid(row=1, column=0, columnspan=1)
untrusted_list.grid_propagate(0)

frame2.rowconfigure(0, weight=1)
frame2.rowconfigure(1, weight=1)

Thread(target=listen).start()
Thread(target=spawn_senders).start()

tk.mainloop()
