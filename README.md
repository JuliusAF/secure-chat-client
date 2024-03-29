# FOREWORD

I realise the code is quite large, but I hope it is not too difficult to understand. I will detail some aspects of the code that may cause confusion, as well as explaining some of the naming conventions I attempted to stick to:

 - The 'parse_x_input' source files and functions define the act of parsing input from the source x. That is, the parse_server_input source file contains functions used to parse input from the server.
 - A function called 'serialize_x' will turn the specified object/command (x) into a byte array.
 - A function starting with 'gen_' generates something, hopefully logically deducible from what follows in the function name.
 - A function called 'handle_' acts on some parsed information. For example, the handle_client_input() function and the other 'handle_client_' functions it called in server_utilities.h act on some parsed input from the client.
 - The source of a definition or function for the server and client is denoted by either an S or C respectively. For example, the definitions for client packet identification as seen in network.h start with 'C_'. This denotes that the identification is for a packet sent from the client. Likewise, the 'gen_c_' functions in client_network.c generate packets for the client to send to the server.

The execution of a user's command is as follows:
 - user types into stdin
 - client.c reads from stdin
 - user input is parsed in parse_user_input.c
 - parsed user input is handled with handle_user_input() in client_utilities.c
 - a packet is created using some 'gen_' function from client_network.c
 - packet is sent over the socket to the server
 - server reads packet in server_utilities.c
 - server parses packet in parse_client_input.c
 - parsed packet from server is handled with handle_client_input() in server_utilities.c
 - database is accessed in database.c based on command invoked
 - information is fetched from the database in database.c
 - using information fetched from the database, a packet is created with some 'gen_' function in server_network.c
 - packet is sent over the network to the client
 - server packet is read in client.c
 - server packet is parsed in parse_server_input.c
 - parsed server input is handled with handle_server_input() in client_utilities.c
 - here most execution comes to an end (a certificate request requires the client send another packet to the server
   and await response)

The functions in cryptography.c, network.c and safe_wrappers.c are used throughout the code and set up a lot of the primitive operations that are part of the protocol, such as encryption/decryption, signing, or sending and reading packets

Another thing to note is that certificate verification verifies the certificate authority that signed a certificate. If make is called again after an executable has already been built and information has been input into the database, all packet authentication from users that existed before the second make call will fail. The verification is defined in verify_x509_certificate() in cryptography.c.

# DATABASE

The database contains two tables; USERS and MESSAGES respectively. It is created in database.c with the function initialize_database();

The database.c and database_utilities.c source files deal with accessing and modifying the database. The functions titled handle_db_* access the database to set or check some state. The fetch_db_* functions fetch some data from the database into an appropriate data structure.

Accessing the database is done using prepared statements and the sqlite3 bind_ interface. This should effectively remove the danger of SQL injections.

### USERS:

The USERS table contains the following fields (no field may be null):

- Username
- Hashed password
- Salt used to hash password
- Certificate
- Initialization vector used during key pair encryption
- Encrypted key pair of user
- Status of user (0 == offline, 1 == online)

The database stores the salt so that on login attempts the given password can be hashed with the respective salt. This process is done in the handle_db_register() and handle_db_login() functions. The register function creates a random salt and hashes the password received from the client, while the login function fetches the salt, uses it on the provided password and compares it with the hash stored in the database.

The certificate is stored so that when two clients want to create an end-to-end encrypted message, the sender can request the certificate of the recipient, verify it belongs to them and is signed by the CA, and encrypt the symmetric key with their public key.

The encrypted key pair can not be decrypted without access to the original password the user entered. It (the encrypted key pair) is sent from the server to the client on a successful login or register attempt. This links the client with their RSA key pair and certificate.

### MESSAGES:

The MESSAGES table contains the following fields:

- Sender of message
- Recipient of message (can be null)
- Message
- Signature
- Initialization vector (can be null)
- Encrypted symmetric key for the sender (can be null)
- Encrypted symmetric key for the recipient (can be null)

The signature stored is the signature that was created when the packet was sent from the client to the server. The packet structure is preserved between client and server when a message is fetched, and the signature is used to validate that the user created the packet.

The initialization vector and symmetric keys are used in conjunction with private messages to retain end-to-end encryption. The message is encrypted using a symmetric key, which is then RSA encrypted and stored in the database such that only the sender and recipient may decrypt them.

# CRYPTOGRAPHY:

Various cryptography protocols are adopted in order to meet the security requirements.

SSL is utilized to verify the server when a client connects to it. This ensures the integrity of data sent from server to client. The client verifies both the server certificate (copied from the serverkeys directory to the clientkeys directory when MAKE is called) and the common name of the expected server with that of the name in the certificate. The expected common name is stored in cryptography.h (it is 'server.example.com'). The SSL connection is established on the server side in server_utilities.c in function worker(), while on the client side it is started in main().

Whenever a user logs in the following process creates and secures their RSA key pair:
- they create a master key that is a function of the submitted plaintext username and password; this is done in cryptography.c with the function gen_master_key().
- This masterkey is used to encrypt and decrypt the RSA key pair (created using create_rsa_pair() in cryptography.c) that belongs to that user using AES-128-CBC encryption defined in apply_aes() in cryptography.c.
- This encrypted key pair is stored in the database and retrieved on login.
- The plaintext password is never saved, nor is it transmitted to the server. As such, the only way the masterkey can be computed is on the client side when a register or login command is invoked.
- The encryption method used is AES-128-CBC and utilizes a random initialization vector (created using create_rand_salt() in cryptography.c) that is also stored on the server. This means the server cannot decrypt the key pair.

The password of a user is hashed twice (using hash_password() in cryptography.c):

- First on the client side before it is sent over to the server. This is without a salt simply to offer basic protection for the users plaintext password.
- The password is hashed again on the server side before it is stored/used for comparison. This hash is with a salt, which is also stored in the database.
- The hashing algorithm used is SHA256.

Usage of X509 certificates:

Any time a client's signature must be checked, the X509 certificate is used. The creation of the certificate is in create_rsa_keypair() in cryptography.c and is as follows:

- An RSA private key is created programmatically.
- This private key is saved to file as a .pem. The name of the file is the hexadecimal version of the hashed username of the person making the request, and thus generating this keypair. The hash is used to avoid any potential problems with invalid file name characters, and because the hash of a username is unique and identifying.
- The trustedthirdparty.sh script is called from execute_ttp_script() in cryptography.c, which is in turn called from gen_x509_certificate() in create_rsa_keypair() in cryptography.c. The shell script creates a certificate signing request titled "hashed username"-csr.pem. This CSR is in turn processed into a certificate with the name "hashed username"-cert.pem. The common name of the certificate is the hash of the username.
- The public key of this certificate is extracted with obtain_pubkey_from_x509() in cryptography.c.

When a signature is checked, both on the server side when a client packet is checked, and on the client side when a a client verifies another client's (or it's own if they are the sender), the certificate is validated against both the CA used to sign the certificate, and the common name in the certificate. If this passes, the public key is extracted and using to verify the signature.

Messages between clients (private messages) are end-to-end encrypted:

(sender refers to the client that started the private message request)

- The sender asks the server for the recipients certificate handle_user_privmsg() in client_utilities.c sends a pubkey_rqst to the server (packet is created with gen_c_pubkey_rqst_packet() in client_network.c).
- The sender verifies the returned certificate and extracts the public key. This is done in handle_server_pubkey_response() in client_utilities.c.
- The sender creates a random key and initialization vector (both 16 bytes using create_rand_salt()).
- The sender encrypts the message using AES-128-CBC with the random key and IV (using apply_aes()).
- The sender creates two copies of the random key. One copy is encrypted with the senders public key, and the other is encrypted with the recipients public key. The encryption and decryption functions are apply_rsa_encrypt() and apply_rsa_decrypt() respectively, located in cryptography.c.
  - These steps are all executed as part of the packet creation in gen_c_privmsg_packet() in client_network.c
- This is all sent to the server and stored in the database (using handle_db_privmsg() in database.c)

The server can therefore not decrypt a private message, and in the event of a database breach the confidentiality of the messages is ensured. The use of the certificate also ensures that the recipient's public key used to encrypt the symmetric actually belongs to them.

Message verification:

When a public or private message is received, the order of the packet is preserved from client to server and server to client. This means the signature of the original packet sent from client to server can be verified to check the identity of the sender. This is done in the function verify_client_payload() in client_utilities.c. It utilizes the sender's certificate. It verifies the CA used to sign it and the common name of the certificate.

Signatures:

Packets from clients to servers are signed where appropriate (it is the hash of the payload that is signed). That is: a login or register request is not signed, as the client does not have their key pair yet. The authentication offered by the password is assumed to be enough. The exit command is not transmitted over the network. The other types of messages are signed by the client. The signing on the client side is done in sign_client_packet() in client_utilities.c. On the server side, the is_client_sig_good() function verifies a client's signature;

Messages from server to client are not signed, as the usage of SSL should add the properties of authentication and integrity already.

# PROTOCOL:

The messages sent from server to client and from client to server differ depending on the type of message sent. However, each packet has a fixed header as described below:

The size of the header is defined in network.h under HEADER_SIZE.
The header consists of:

- 4 bytes for length of data
- 2 bytes for identification code
- 4 bytes for length of signature
- 256 bytes for the signature. This field may be left empty depending on what type of packet is sent and from/to whom

## From client to server communication:

The following section describes the types of packets sent from client to server. These differ depending on the command invoked. The possible commands are exit, login, register, public message, private message and users.

### Exit command:

The exit command need not be transmitted over the server, although it can be. A client side exit will still be noticed on the server side through read().

### Register command:

When a user invokes the register command, the user provides a username and password. The username stays in the plaintext form that it was submitted. The password is hashed with sha256. In addition to this, the client creates a public/private key pair for the current register request. This key pair is encrypted with AES-128-CBC using a master key as described above. The server stores a client certificate and the encrypted form of both the public and private key. As such, these must be transmitted to the server.

The register command requires only one packet be sent from client to server, which is as follows:

The identification for a register command packet from client to server is C_MSG_REGISTER.

- 20 bytes for username
- 32 bytes for hashed password (sha256)
- 4 bytes for size of certificate
- variable size for certificate
- 16 bytes for initialization vector
- 4 bytes for size of encrypted keys
- variable size for encrypted keys

This message is compiled in client_network.c with the function gen_c_register_packet() and its helper functions.

### Login command:

When a user attempts to login, they provide a username and password. The username is sent over in plaintext while the password is hashed using SHA256 without a salt. The login packet on the client side is created using gen_c_login_packet() in client_network.c.

The identification for a login command from the client is C_MSG_LOGIN

- 20 bytes for username (defined in USERNAME_MAX)
- 32 bytes for the hashed password

### Private message command:

When a user wants to transmit a private message, they must first ask the server for the recipient's public key (transmitted as an X509 certificate). When the client does this, it also sends with it the information it wants to transmit. This is done so that it need not be buffered/saved in memory across commands. The message is formatted client side using create_formatted_msg() in client_network.c. The process is as follows:

Using the master key created at login time, it encrypts the private message with AES-128-CBC (using an initialization vector). This ensures that the server, should it try to, can not decrypt the message. This information, along with the recipient's name whose certificate is requested, is sent to the server that processes the request. The return value from the server includes all the information sent from the client, as well as the certificate and the signature of the original packet. The order is preserved. The signature can thus be checked by the client to make sure the data it sent over remained unchanged. This request is made with gen_c_pubkey_rqst_packet() in client_network.c.

The identification is defined in C_META_PUBKEY_RQST. The makeup of the packet is as follows:

- 20 bytes for the username whose public key is requested
- 16 bytes for the IV used to encrypt the message
- 4 bytes for the size of the encrypted message
- variable size for the encrypted message

In the event of a successful return packet from the server, the client then creates the the private message packet. This entails the decryption of the message (encrypted with the master key), then encrypting it as described in the CRYPTOGRAPHY section. The client's certificate (i.e the certificate of the sender) is also added to the packet, as it must be transmitted anyway when a message packet is sent from the server to clients for verification purposes. The private message is created in gen_c_privmsg_packet() in cryptography.c:

The identification is C_MSG_PRIVMSG.

- 4 bytes for size of the certificate
- variable size for the certificate
- 20 bytes for sender of message
- 4 bytes for the encrypted message size
- variable size of the message
- 20 bytes for the username of the recipient
- 16 bytes for the initialization vector used to encrypt the message
- 4 bytes for the size of the symmetric key encrypted for the sender
- variable amount of bytes for the encrypted symmetric key
- 4 bytes for the size of the recipient-encrypted symmetric key
- variable size for the recipient's symmetric key

### Public message command:

A public message does not need to be encrypted. The public key of the user who sent the message is added as well so that when clients receive the packet from the server, they can verify the users identity. This packet is created using gen_c_pubmsg_packet(). The make up is as follows:

The identification code is C_MSG_PUBMSG

- 4 bytes for size of the certificate
- variable size for the certificate
- 20 bytes for sender of message
- 4 bytes for the size of the message
- variable size for the message

### Users command:

A request to see online users requires no data to be transmitted to the server. However, signatures are implemented on the payload of a packet. As such a constant text is added to the request so that it may be signed for verification on the server side:

The identification code is C_MSG_USERS

- LOGIN_REQUEST_SIZE is the size of the string submitted

## From server to client communication

The server only ever writes to the client in response to client input. As such, the data is reactionary, and based on whether a given client command executed successfully or not, a packet containing either an error message or data is sent. The identification of packets is defined in network.h.

When an error occurs that the user should be made aware of, an error message is sent to the client. Other than when a register or login fails, all error messages have the id S_MSG_GENERIC_ERR. All error messages are created using gen_s_error_packet() in server_network.c. The makeup is simple:

- Variable size for the error message. The size of the message is thus the size of the payload stored in the header.

### Exit command:

Nothing is written to the client.

### Register command:

A register command can either succeed of fail depending on whether the given username is reserved or the user is logged on (although this is also checked client side, so this error should not occur).

##### On register success:

The identification for a packet on a successful registration is S_META_REGISTER_PASS

When a user successfully registers, the server logs that client in. This means that the return packet for login and register are the same. As such, the packet returned contains the RSA key pair that is stored in the database for that user. A successful register packet is created using gen_s_userinfo_packet() in server_network.c.

The packet is as follows:

The identification is S_META_REGISTER_PASS

- 16 bytes for the initialization vector utilized when encrypting the key pair
- 4 bytes for the size of the key pair
- variable size for the encrypted key pair

##### On register failure:

On failure, the identification is S_META_REGISTER_FAIL.

The packet returned contains an error message on why the register failed:

- variable size for the error message

### Login command:

As stated above, the packets as a response to a login request are virtually the same as for registration. The only difference is that the identification codes are different.

#### On login success:

The packet is as follows:

The identification is S_META_LOGIN_PASS

- 16 bytes for the initialization vector utilized when encrypting the key pair
- 4 bytes for the size of the key pair
- variable size for the encrypted key pair

####

On failure, the identification is S_META_LOGIN_FAIL.

The packet returned contains an error message on why the login failed:

- variable size for the error message

### Private message command:

When a client requests a certificate, the server fetches it and sends it back to the client. It also preserves the original packet sent from the client. As such the makeup is:

The identification is S_META_PUBKEY_RESPONSE.

- 4 bytes for size of the certificate
- Variable size for the certificate
- 20 bytes for the username whose certificate is requested
- 16 bytes for the IV used to encrypt the message
- 4 bytes for the size of the message
- variable size for the message

Since all workers must be notified when the database is updated with a message, the server does not send a message directly to the user who sent it. Instead, the worker notifies the server that a message has been placed into the database, and the server then notifies all active workers of this. The worker who handled the message in the first place thus acts on the servers message in the same way as all other workers do. The function that handles this is handle_db_msg_update() in server_utilities.c. This process is the same for public and private messages.

A private message is created using gen_s_msg_packet() in server_network.c. The makeup of a private message packet sent from the server to a user is as follows:

The identification code is S_MSG_PRIVMSG.

- 4 bytes for length signature of original packet
- Variable size for signature
- 4 bytes for size of certificate
- Variable size for certificate
- 20 bytes for the sender of the message
- 4 bytes for size of message
- Variable size for message
- 20 bytes for username of recipient
- 16 bytes for initialization array used to encrypt message
- 4 bytes for size of encrypted symmetric key for sender
- Symmetric key for sender
- 4 bytes for recipient symmetric key size
- Recipient symmetric key size

If a failure occurs a generic error message is sent as described above.

### Public message command:

The makeup of a public message is like a private message but missing the encryption details and the recipient. As such, it is also created in gen_s_msg_packet() in server_network.c (a private message simply adds more to it).
The makeup is as follows:

The identification code is S_MSG_PUBMSG.

- 4 bytes for length signature of original packet
- Variable size for signature
- 4 bytes for size of certificate
- Variable size for certificate
- 20 bytes for username of sender
- 4 bytes for size of message
- Variable size for message

### Users command:

A response to a users request is either an error as described above or the list of active users. This list is simply a character array of space delimited names. The list of users is fetched using fetch_db_users() in database.c and the packet is created with gen_s_users_packet() in server_network.c. The makeup of the packet is as follows:

The identification code is S_MSG_USERS.

- Variable size for list of users. Size is thus stored in header.

# SECURITY GOALS

The following security goals have been addressed:

- Private messages are encrypted with end-to-end encryption, and thus Mallory cannot get information about them should she compromise the database. The public key of the recipient is wrapped in an X509 certificate, thus validating the authenticity of the public key.

- Signatures are used to verify a client's message, both by the server and by other users. The signature is applied to the entire payload sent by a user, and thus if any aspect of the packet is changed it would be detected. This tries to address the security goal of Mallory not being able to send or modify messages by other users. The signatures are once again checked with public keys obtained from an X509 certificate.

- Passwords are hashed with salts before being stored in the database, and even before storage are hashed on the client side to offer (relatively weak since no salt) protection for the plaintext password. Private keys are encrypted with AES-128-CBC and a random initialization vector. This should provide confidentiality for a user's password and private key.

- An attempt has been made to cover all possibilities of buffer overflows:
  - All messages are parsed by the program that receives them.
    - User input is parsed by the client in parse_user_input.c.
    - Packets from the client to the server are parsed in parse_client_input.c.
    - Packets from server to client are parsed in the parse_server_input.c files.
  - The functions in these files, when dealing with memory (such as memcpy()), always check that a read/copy does not exceed the appointed memory.
  - Wherever possible, functions are used that explicitly specify the size of the operation.
  - There are (as far as I have found) no memory leaks in an active running process that terminates properly. (If the program is killed, some memory is not freed at termination).
  - Sizes are explicitly checked. The function to read from a socket ensures that the specified data is read. A packet header's payload size is thus ensured to be accurate.

- The programs do not modify any files other than chat.db (for the server) and files in the clientkeys directory. The CA and server certificates are created when make is called and copied into other folders such that the certificates can be accessed without breaking the non-functional requirement of not accessing another's folder.
