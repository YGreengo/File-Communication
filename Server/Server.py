# Name: Yarden Green
# ID: 313925976

import base64
import socket
import struct
import uuid
import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from pathlib import Path
from Crypto.Util.Padding import pad, unpad
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

crctab = [0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc,
        0x17c56b6b, 0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f,
        0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a,
        0x384fbdbd, 0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8,
        0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
        0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e,
        0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84,
        0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027,
        0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022,
        0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077,
        0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c,
        0x2e003dc5, 0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1,
        0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb,
        0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
        0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d,
        0x40d816ba, 0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f,
        0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044,
        0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689,
        0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683,
        0xd1799b34, 0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59,
        0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c,
        0x774bb0eb, 0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e,
        0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
        0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48,
        0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2,
        0xe6ea3d65, 0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601,
        0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604,
        0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6,
        0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad,
        0x81b02d74, 0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7,
        0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd,
        0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
        0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b,
        0x0fdc1bec, 0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679,
        0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12,
        0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af,
        0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5,
        0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06,
        0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03,
        0xb1f740b4]

UNSIGNED = lambda n: n & 0xffffffff

#  calculates crc
def memcrc(b):
    n = len(b)
    i = c = s = 0
    for ch in b:
        tabidx = (s>>24)^ch
        s = UNSIGNED((s << 8)) ^ crctab[tabidx]

    while n:
        c = n & 0o377
        n = n >> 8
        s = UNSIGNED(s << 8) ^ crctab[(s >> 24) ^ c]
    return UNSIGNED(~s)

# put a lock to critical actions
thread_local = threading.local()
lock = threading.Lock()

#user class
class User:
    def __init__(self, user_id, username, public_mod=None, public_exponent=None):
        self.user_id = user_id
        self.username = username
        self.public_mod = public_mod
        self.public_exponent = public_exponent
        self.files = []

#add files to file list
    def add_file(self, file_name):
        self.files.append(file_name)

#saves file
def save_file(file_name, content):
    # Check if the folder exists
    folder_name = "client files"
    if not os.path.exists(folder_name):
        # If the folder doesn't exist, create it
        os.makedirs(folder_name)

    # Save the file in the specified folder
    filepath = os.path.join(folder_name, file_name)
    with open(filepath, 'wb') as file:
        file.write(content)


#RSA encryption for aes key
def rsa_encrypt(data, public_key_modulus, public_key_exponent):

    public_key = RSA.construct((public_key_modulus, public_key_exponent))

    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_data = cipher_rsa.encrypt(data)

    # return the encrypted AES key
    return encrypted_data

#unpads and decrypt
def unpad_and_decrypt(data, key):
    iv = bytes(AES.block_size)
    decipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = decipher.decrypt(data)
    plain = unpad(decrypted_data, AES.block_size)
    return plain


# handles registration for request 1025
def handle_registration(username):
    try:
        # get the lock
        lock.acquire()
        # searches for a username that is taken
        # creates a new user and adds to list
        for user in user_list:
            if user.username == username:
                return 1601

        user_id = str(uuid.uuid4()).replace('-', '')
        user_id = bytes.fromhex(user_id)
        new_user = User(user_id.hex(), username)
        user_list.append(new_user)
        return user_id
    except Exception as e:
        print(f"Error handling registration: {e}")
        return None
    finally:
        lock.release()

# handles request 1025 for registration
def handle_request_1025(data, client_socket):
    try:
        # Unpack the request
        client_id, version, request_num, received_payload_size, user_name_bytes = struct.unpack('<16sBHI255s', data)
        user_name = user_name_bytes.rstrip(b"\x00").decode('utf-8')  # remove trailing null bytes
        user_id = handle_registration(user_name)  # send to registration details function

        print(f"Registering user: {user_name}")

        # check if registration failed
        if user_id == 1601:
            return_code = 1601
            return_payload_size = 0
            return_pack = struct.pack('<BHI', version, return_code, return_payload_size)
            client_socket.send(return_pack)  # Send response to client
            print(f"User {user_name} registration failed")
            return

        # registration successful
        return_code = 1600
        return_payload = user_id
        return_payload_size = 16
        return_pack = struct.pack('<BHI16s', version, return_code, return_payload_size, return_payload)

        # send the response to the client
        client_socket.send(return_pack)

        print(f"User {user_name} created")

    except struct.error as e:
        print(f"Error processing client request 1025: {e}")

    except Exception as e:
        print(f"An error occurred while handling request 1025: {e}")


# handles requests 1026 and 1027
def handle_requests_1026_7(data,request,client_socket):
        #if the request is 1026
        if request == 1026:
            code = 1602
            #unpack the request
            try:
                client_id, version, request_num, received_payload_size, user_name_bytes, public_key_mod, public_key_exp \
                    = struct.unpack('<16sBHI255s128sB', data)
                user_name = user_name_bytes.rstrip(b"\x00").decode('utf-8')
                # get the public key mod
                public_key_modulus_int = int.from_bytes(public_key_mod)
                #searcher for user id in user list
                for user in user_list:
                    #if found
                    if user.user_id == client_id.hex():
                        my_user = user
                        user.public_mod = public_key_modulus_int
                        user.public_exponent = public_key_exp
                        break

            except Exception as e:
                print(f"there was an error handling request 1026: {e}")
        #request is 1027
        else:
            #unpack the request
            try:
                client_id, version, request_num, received_payload_size, user_name_bytes = struct.unpack('<16sBHI255s',
                                                                                                        data)

                code = 1605
                user_found = 0
                #searches for user in user list and stop
                for user in user_list:
                    if user.user_id == client_id.hex():
                        #if found, set the key
                        user_found = 1
                        if(user.public_mod and user.public_exponent):
                            public_key_modulus_int = user.public_mod
                            public_key_exp = user.public_exponent
                        break
                #if user not found return the correct reply
                if not user_found == 1 or (not public_key_exp and not public_key_modulus_int):
                    print(f"user id: {client_id.hex()} not found")
                    payload_size = 16
                    code = 1606
                    reply_pack = struct.pack('<BHI16s', version, code, payload_size, client_id)
                    client_socket.send(reply_pack)
                    return
            except Exception as e:
                print(f"there was an error handling request 1027: {e}")
        #create random aes key
        aes_key = get_random_bytes(32)
        #set the thread global aes key
        thread_local.aes_key = aes_key
        #encrypt the aes key
        encrypted_aes = rsa_encrypt(aes_key, public_key_modulus_int, public_key_exp)

        payload_size = len(encrypted_aes)
        #packs the request and sends
        reply_pack = struct.pack('<BHI16s128s', version, code, payload_size, client_id, encrypted_aes)
        client_socket.send(reply_pack)
        return

#handles request 1028
def handle_request_1028(data,client_socket):
    try:
        #initialize empty byte array
        file_contents = bytearray()
        check = 0
        #set chunk size
        chunk_size = 734

        # unpack the first chunk
        (client_id, version, request_num, received_payload_size, content_size, orig_file_size, chunk_num, total_chunks,
         file_name, message_content) = struct.unpack(f'<16sBHIIIHH255s{chunk_size}s', data)
        file_contents.extend(message_content)
        #while there are still chunks to get, iterate
        while chunk_num <= total_chunks:
            check+=1
            try:
                #receive another message with another pack
                received_data = client_socket.recv(1024)
                (client_id, version, request_num, received_payload_size, content_size, orig_file_size,
                 chunk_num, total_chunks, file_name, message_content) = struct.unpack(
                    f'<16sBHIIIHH255s{chunk_size}s', received_data)

                # if its the last chunk - handle padding
                if chunk_num == total_chunks:
                    fixed_file_content = message_content.rstrip(b"\0")
                    file_contents.extend(fixed_file_content)
                    check+=1
                    break
                else:
                    #if its not the last chunk just add it to byte array
                    fixed_file_content = message_content
                file_contents.extend(fixed_file_content)
            except Exception as e:
                print(f"there was an error handling getting chunk {chunk_num}: {e}")
        print(f"got all {check} chunks")
        # unpads and decrypts the file contens
        decrypted_file_content = unpad_and_decrypt(file_contents, thread_local.aes_key)
        #get the original file content
        original_file = decrypted_file_content[:orig_file_size]
        #generate crc for the file
        file_crc = memcrc(original_file[:orig_file_size])
        print(f"got crc: {file_crc}")
        # set the reply pack and send
        payload_size = 279
        code = 1603
        reply_pack = struct.pack('<BHI16sI255sI', version, code, payload_size, client_id, content_size, file_name,
                                 file_crc)
        client_socket.send(reply_pack)
        thread_local.file_content = original_file
    except Exception as e:
        print(f"An error occurred while handling request 1028: {e}")

#handles requests 1029 and 1030 and 1031
def handle_request_1029_30_31(data,request_code,client_socket):
    try:
        #unpacks the request
        client_id, version, request_num, received_payload_size, file_name = struct.unpack('<16sBHI255s',
                                                                 data)
        # if 1029 or 1031 request - they have the same reply
        if request_code == 1029 or request_num == 1031:
            code = 1604
            payload_size = 16
            reply_pack = struct.pack('<BHI16s', version, code,payload_size, client_id)
            client_socket.send(reply_pack)
            # if request 1029 got CRC confirmation , save the file and append it to user file list
            if request_num == 1029:
                print(f"got confirmation for crc from used id: {client_id.hex()}")

                for user in user_list:
                    #search for user in users list
                    if user.user_id == client_id.hex():
                        #decode and format the file name
                        formatted_file_name = file_name.rstrip(b"\0").decode('utf-8')
                        #add to user file list
                        user.add_file(formatted_file_name)
                        print(f"file name added to user {formatted_file_name}")
                        save_file(formatted_file_name, thread_local.file_content)
            print(f"request {request_num} handled")

        else:
            print("waiting for request 1028 again")
            return
    except Exception as e:
        print(f"An error occurred while handling request 1029: {e}")



# reads port from port file
def read_port():
    global server_port
    if port_file.exists():
        with open(port_file, 'r') as f:
            server_port = int(f.readline())
    else:
        print("there is no port.info file. working on default")
        server_port = 1256


# handles clients requests
def handle_client(client_socket, client_address):
    try:
        while True:

            received_request = client_socket.recv(1024)
            if not received_request:
                print(f"Client {client_address} disconnected.")
                break
            request_num = struct.unpack('<H', received_request[17:19])[0]
            client2_id = struct.unpack('<16s',received_request[0:16])[0]
            print(f"client {client2_id.hex()} sent a request")
            print(f"request number: {request_num}")
            if request_num == 1025:
                handle_request_1025(received_request, client_socket)
                print("Request 1025 handled")

            elif request_num == 1026 or request_num == 1027:
                handle_requests_1026_7(received_request,request_num, client_socket)
            elif request_num == 1028:
                handle_request_1028(received_request, client_socket)
            elif request_num ==1029 or request_num ==1030 or request_num == 1031:
                handle_request_1029_30_31(received_request,request_num, client_socket)

            else:
                print(f"Unknown request type: {request_num}")

    except Exception as e:
        print(f"An error occurred while handling client {client_address}: {e}")

    finally:
        client_socket.close()


port_file = Path("port.info")
user_list = []
version = 3

server_ip = '127.0.0.1'
server_port = None
client_socket = None

# main function loops
if __name__ == "__main__":
    try:

        read_port()
        kdc_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        kdc_server.bind((server_ip, server_port))
        kdc_server.listen()
        print(f"Socket is listening on IP address {server_ip}, on port {server_port}")

        while True:
            client_socket, client_address = kdc_server.accept()
            print(f"Accepted connection from {client_address}")

            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()  # opens thread for new user

    except Exception as e:
        print(f"Error handling requests: {e}")

    finally:
        kdc_server.close()
