#ifndef WEBSOCKETCLIENT_H_
#define WEBSOCKETCLIENT_H_



// CRLF characters to terminate lines/handshakes in headers.
#define CRLF "\r\n"


// ACTION_SPACE is how many actions are allowed in a program. Defaults to 
// 5 unless overwritten by user.
#ifndef CALLBACK_FUNCTIONS
#define CALLBACK_FUNCTIONS 1
#endif

#define SIZE(array) (sizeof(array) / sizeof(*array))

class WebSocketClient {
public:


    // Handle connection requests to validate and process/refuse
    // connections.
    bool handshake(Client &client);
    
    // Get data off of the stream
    char* getData();

    // Write data to the stream
    void sendData(char *str);

    void disconnect();

    char *path;
    char *host;

    void sendEncodedData(char *str);


private:
    Client *socket_client;
    unsigned long _startMillis;

    const char *socket_urlPrefix;

    // Discovers if the client's header is requesting an upgrade to a
    // websocket connection.
    bool analyzeRequest();

    
    // Disconnect user gracefully.
    void disconnectStream();
    
    int timedRead();

    
    int charinstr(char* text, int size, char* string);
    bool array_cmp(char *a, char *b, int len_a, int len_b);
};



#endif