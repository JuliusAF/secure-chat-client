# DATABASE

The database contains two tables; USERS and MESSAGES respectively. It is created in database.c with the function initialize_database();

### USERS:

The USERS table contains the following fields:

- Username
- Hashed password
- Salt used to hash password
- Public key
- Length of the public key
- initialization vector used during key pair encryption
- Encrypted key pair
- Length of encrypted key pair
- Status of user (0 == offline, 1 == online)

The database stores the salt so that on login attempts the given password can be hashed with the respective salt.

The public key is stored so that when two clients want to create an end-to-end encrypted message, the sender can request the public key of the recipient.

The encrypted key pair can not be decrypted without access to the original password the user entered. It is sent from the server to the client on a successful login or register attempt. This links the client with their RSA key pair.

The sizes for the public key and encrypted key pair is stored for verification purposes when sqlite3 returns the blob of either of these two fields.

### MESSAGES:

# CRYPTOGRAPHY:

Various cryptography protocols are adopted in order to meet the security requirements.

SSL is utilized to verify the server when a client connects to it. This ensures the integrity of data sent from client to server. The client verifies both the server certificate stored in serverkeys/ and the common name of the expected server with that of the name in the certificate. The expected common name is stored in cryptography.h.

Whenever a user logs in, they create a master key that is a function of the submitted plaintext username and password. This masterkey is used to encrypt and decrypt the RSA key pair that belongs to that user. This key pair is stored in the database and retrieved on login. The plaintext password is never saved, nor is it transmitted to the server. As such, the only way the masterkey can be computed is on the client side when a register or login command is invoked. The encryption method used is AES-128-CBC and utilizes a random initialization vector that is also stored on the server. This means the server can not decrypt the key pair, and an attacker would have to gain access to the memory of the client program to access the master key.

The password of a user is hashed twice:

- First on the client side before it is sent over to the server. This is without a salt simply to offer basic protection for the users plaintext.
- The password is hashed again on the server side before it is stored/used for comparison. This hash is with a salt, which is also stored in the database.
- The hashing algorithm used is SHA256.

Messages between clients (private messages) are end-to-end encrypted:

(sender refers to the client that started the private message request)

- The sender asks the server for the recipients public key.
- The sender creates a random key and initialization vector.
- The sender encrypts the message using AES-128-CBC with the random key and IV.
- The sender creates two copies of the random key. One copy is encrypted with the senders public key, and the other is encrypted with the recipients public key.
- This is all sent to the server and stored in the database

The server can therefore not decrypt a private message, and in the event of a database breach the confidentiality of the messages is ensured.


# PROTOCOL:

The messages sent from server to client and from client to server differ depending on the type of message sent. However, each packet has a fixed header as described below:

The size of the header is defined in network.h under HEADER_SIZE
The header consists of:

- 4 bytes for length of data
- 2 bytes for identification code
- 4 bytes for length of signature
- 256 bytes for the signature. This field may be left empty depending on what type of packet is sent and from/to whom

## From client to server communication:

The following section describes the types of packets sent from client to server. These differ depending on the command invoked. The possible commands are exit, login, register, public message, private message and users.

### Exit command:

The exit command need not be transmitted over the server although it can be. A client side exit will still be noticed on the server side with read()

### Register command:

When a user invokes the register command, the user provides a username and password. The username stays in the plaintext form that it was submitted. The password is hashed with sha256. In addition to this, the client creates a public/private key pair for the current register request. The server stores a client public key and the encrypted form of both the public and private key. As such, these must be transmitted to the server.

The register command requires only one packet be sent from client to server, which is as follows:

The identification for a register command packet from client to server is C_MSG_REGISTER.

- 20 bytes for username
- 32 bytes for hashed password (sha256)
- 4 bytes for size of public key
- variable size for public key
- 16 bytes for initialization vector
- 4 bytes for size of encrypted keys
- variable size for encrypted keys

This message is compiled in client_network.c with the function gen_c_register_packet() and its helper functions.

### Login command:

### Private message command:

### Public message command:

### Users command:

## From server to client communication

The server only ever writes to the client in response to client input. As such, the data is reactionary, and based on whether a given client command executed successfully or not, a packet containing either an error message or data is sent. The identification of packets is defined in network.h

### Exit command:

Nothing is written to the client.

### Register command:

A register command can either succeed of fail depending on whether the given username is reserved or the user is logged on (although this is also checked client side, so these errors should not occur).

###### On register success:

The identification for a packet on a successful registration is S_META_REGISTER_PASS

When a user successfully registers, the server logs that client in. This means that the return packet for login and register are the same. As such, the packet returned contains the RSA key pair that is stored in the database for that user.

The packet is as follows:

- 16 bytes for the initialization vector utilized when encrypting the key pair
- 4 bytes for the size of the key pair
- variable size for the encrypted key pair

###### On register failure:

On failure, the identification is S_META_REGISTER_FAIL.

The packet returned contains an error message on why the register failed:

- variable size for the error message

### Login command:

### Private message command:

### Public message command:

### Users command:
