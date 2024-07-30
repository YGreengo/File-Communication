# File-Communication
--Description--
This project implements a secure file transfer system between a client and server, featuring encrypted communication. The server is written in Python, and the client is written in C++ using Boost for networking and Crypto++ for encryption.

--Key Features--
Hybrid Encryption Protocol: Utilizes RSA to encrypt a symmetric AES key, which is then used to encrypt the file content.
Client-Server Communication: The client reads data from a configuration file (Username, IP address, port, and filename).
User Registration: The client registers with the server and ensures unique user details.
Key Exchange: The client sends its RSA public key to the server. The server generates a new AES key, encrypts it with the client’s public key, and sends it back.
Secure File Transfer: The client securely sends the specified file to the server using encrypted communication. The server stores the received file in a designated folder.

--Workflow--
Client Initialization: Reads username, server IP, port, and file name.
User Registration: Ensures no duplicate user on the server.
Public Key Transmission: Client sends its RSA public key to the server.
AES Key Generation and Exchange: Server creates an AES key, encrypts it with the client's public key, and sends it to the client.
Secure File Transfer: Client encrypts the file with the AES key and sends it to the server, which stores it securely.

--How to Run--
Start the server by running the Python server script.
Configure the client with the server details and file information.
Run the client to initiate secure communication and file transfer.

--Dependencies--
Server: Python 3.x
Client: C++11 or higher, Boost, Crypto++

--Usage--
This project demonstrates a practical implementation of secure file transfer using hybrid encryption techniques, suitable for scenarios requiring secure communication over a network.

