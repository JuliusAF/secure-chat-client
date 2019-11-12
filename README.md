As of right now, the application does not implement any proper network protocol. It simply sends plain text over the network, and this is parsed both on the server and the client side. I assumed that getting the application to (mostly) work would be more important, even if the network protocol is not fully developed. As it stands, adding the network protocol such as (de)serializing structs, adding and removing metadata and concatenating them into one packet should only add another layer to the program. The types the application uses right now to access the database etc. will remained
unchanged. I will add the planned implementation of the networking stuff at the bottom.

Almost all basic functionalities work if commands are input through the terminal, but I couldn't get automatic testing to work. If I exit the program after end of file I can not catch messages sent from the server in time. The problem is that I exit my program when stdin reaches end of file, and when input is entered from a file, I'm guessing exiting of the program happens too fast to catch the data sent from the server since they are all in the same loop. The other problem is that because of the lack of network protocol, the reading of the plain text over the sockets causes information to be lost. As such, it is failing to properly display all the past messages when a user logs in as some of these messages are lost.

SECURITY:

Parsing:

The client program parses all user input according to the rules specified in the assignment documentation. It sets a maximum length for usernames, passwords and messages (parser.h) that is utilized through the rest of the program. This should make it harder to have buffer overflows.

The parser creates a node that describes the user input. Along with a type for each of the commands, it includes an error type that contains an error string explaining what is wrong about the user input. I have tested the parser relatively extensively and it should be able to find every user input that does no conform to the declared syntax.

Network:

Because I have not yet implemented a proper network protocol, there is little in the way of security measures. The one thing I do is parse the input from the client in the same way the client parses input from the user.

Database:

I have never used sqlite3 before so I lack a lot of knowledge on safety aspects as well as good ways to format the sqlite3 code and the sql statements. I have read that using the sqlite3_bind operators on a prepared statement is a good way to combat SQL injections, which I have attempted to do.

Right now passwords are stored as plain text in the database. This will be changed, such as storing the hashes of passwords instead of the passwords themselves.





PLANNED PROTOCOL:

Each packet will contain a header of fixed size that includes the following:
- Four bytes that act as an identification number for the packet
- Four bytes to indicate the size of the data
- Four bytes that contain a checksum to error check the packet
- Eight bytes that contain an identification string that specifies what the
  nature of the data in the packet is. This is different based on whether the packet
  came from client to server or vice versa.

CLIENT TO SERVER

For client to server communication, the client sends parsed input data to the server, with the length and content of the data part of the packet mostly fixed to one size. There are only three possibilities for variable user input that does not include the command literals (such as "/exit"). These are a username, a password and a message. Dependent on the command invoked, some or none of these fields receive input. The maximum sizes (in bytes) for each variable input is:
- Username = 20
- Password = 24 (this number will likely change because passwords will be transmitted as their hashes)
- Message = 200

As such, the data part of the packet sent from client to server is a serialized unsigned char array with a fixed length of 252 bytes. The make up of the data is as follows:
- The first sizeof(int) bytes contain the code that corresponds to the type of message
  that is being sent in the packet.
- The next 20 bytes contain the username
- the next 24 bytes contain the password
- The next 200 bytes contain the message

Should a given input not fully occupy its respective field, the remainder of the bytes are initialized to null terminators.

The server takes this array of unsigned characters and deserializes it back into the struct that holds user input. This struct is defined in "parser.h" and is the same struct that user input is initially parsed into on the client program.

SERVER TO CLIENT

The server can send the client data of variable size, depending on the nature of the contents. The server can send the client either information obtained from the database (public and private messages) or error messages that can only be identified server side because they require database access. The makeup of these packets are as follows:
- A variable amount of bytes containing the data sent from server to client.
  The size of this data is in the header.
