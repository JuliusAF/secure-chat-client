As it currently stands I tried only to get the required functionality for deadline
A working. I did not manage to implement a proper networking protocol. Right now I
am simply sending messages in plain text between server and client, and straight up
parsing the input on both ends. The basic functionalities work if input through the
terminal but I couldn't get automatic testing to work. If I exit the program after end
of file I can not catch messages sent from the server in time.






Network Protocol:

The packets sent from client to server and from server to client are different.

For client to server communication, the client sends parsed input data to the server, with the length and content of the data part of the packet fixed to one size. There are only three possibilities for variable user input that does not include the command literals (such as "/exit"). These are a username, a password and a message. Dependent on the command invoked, some or none of these fields receive input. The maximum sizes (in bytes) for each variable input is:
- Username = 20
- Password = 24
- Message = 200

As such, the data part of the packet sent from client to server is a serialized unsigned char array with a fixed length of 252 bytes. The make up of the data is as follows:
- The first sizeof(int) bytes contain the code that corresponds to the type of message
  that is being sent in the packet.
- The next 21 bytes contain the username
- the next 25 bytes contain the password
- The next 201 bytes contain the message

The chunks of data are always one byte larger than the sizes of their
fields and should always contain a null terminator.

Should a given input not fully occupy its respective field, the remainder of the bytes are initialized to null terminators.

The server takes this array of unsigned characters and deserializes it back into the struct that holds user input. This struct is defined in "parser.h" and is the same struct that user input is initially parsed into on the client program.
