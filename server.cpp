#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>


using namespace std;

int main(){
    cout << "Trying to find a connection......\n";
    while (true)
    {
    
    int server, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[2000] = {0};

    server = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;

    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt ,sizeof(opt)) < 0){
        perror("setsockopt");
        return 1;
    }
    

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server, (struct sockaddr*)&address, sizeof(address)) < 0){
        perror("bind failed");
        return 1;
    }

    if (listen(server, 3) < 0){
        perror("listening failed");
        return 1;
    }

    cout << "Waiting for a message...\n";

    client_socket = accept(server, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    
    read(client_socket, buffer, 2000);

    cout << "Found the messages: " << buffer << "\n";

    close(client_socket);
    close(server);
} return 0;}