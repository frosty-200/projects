#include <iostream>          // For input/output
#include <sys/socket.h>      // For socket functions
#include <arpa/inet.h>       // For inet_pton and sockaddr_in
#include <unistd.h>          // For close() function
#include <cstring>
#include <string>

using namespace std;


int main(){
    while (true)
    {
    
    int sock = 0;
    struct sockaddr_in serv_addr;
    string mess;
    cout << "Type the message here: \n";
    // string message = "hello there";

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        cout << "error with sock size";
        return 1;
    }
    

    serv_addr.sin_family = AF_INET; // this is making the server address ipv4
    serv_addr.sin_port = htons(8080); // this is making the server address port number

    if (inet_pton(AF_INET, "10.153.2.142", &serv_addr.sin_addr) <= 0){ // this converts text-ip to binary-ip. the &serv_addr.sin_addr is where to
        cerr << "invalid address";                                  // store the binary stuff
        return 1;
    }
    
    

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){ // this is the call for the connection, making the socket using the structure of 
        cerr << "error with connection";                                     // socket and passing the preset serv_addr along with the data size it needs
        continue;
    }

    getline(cin, mess);
    send(sock, mess.c_str(), mess.length(), 0);

    cout << "Message sent... \n";

    close(sock);

    

}
return 0;
}