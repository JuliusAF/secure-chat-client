Network Protocol:

The packets sent from client to server and from server to client are different.

For client to server communication, the client sends parsed input data to the server, with the length and content of the data part of the packet fixed to one size. There are only three possibilities for variable user input that does not include the command literals (such as "/exit"). These are a username, a password and a message. Dependent on the command invoked, some or none of these fields receive input. The maximum sizes (in bytes) for each variable input is:
- Username = 20
- Password = 24
- Message = 200

As such, the data part of the packet sent from client to server is a serialized unsigned char array with a fixed length of 252 bytes. The make up of the data is as follows:
- bytes 0 to 7 contain the command invoked, written in plaintext:
  - "LOGIN", "REGISTER", "USERS", "EXIT", "PRIVMSG", "PUBMSG"
- bytes 8 to 27 contain the username
- bytes 28 to 51 contain the password
- bytes 52 to 251 contain the message

Should a given input not fully occupy its respective field, the remainder of the bytes are initialized to null terminators.

The server takes this array of unsigned characters and deserializes it back into the struct that holds user input. This struct is defined in "parser.h" and is the same struct that user input is initially parsed into on the client program.
