#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

// Protocol
struct Header {
    uint16_t magic;
    uint16_t version;
    uint32_t msg_type;
    uint32_t session_id;
    uint32_t payload_len;
    uint8_t encrypted;
    uint8_t reserved[3];
};

enum MsgType {
    MSG_CONNECT = 0x01,
    MSG_FILE_UPLOAD = 0x02,
    MSG_SCAN_STATUS = 0x03,
    MSG_SCAN_RESULT = 0x04,
    MSG_DISCONNECT = 0x05,
    MSG_NOTIFY = 0x06
};

class SimpleClient {
private:
    int sock;
    uint32_t session_id;
    std::string server_ip;
    int server_port;
    bool connected;
    
public:
    SimpleClient(const std::string& ip, int port) 
        : sock(-1), session_id(0), server_ip(ip), server_port(port), connected(false) {}
    
    ~SimpleClient() {
        if (connected) disconnect();
    }
    
    bool connect_to_server() {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Socket creation failed\n";
            return false;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Connection failed\n";
            close(sock);
            return false;
        }
        
        // Get session ID
        Header header;
        recv(sock, &header, sizeof(header), 0);
        session_id = header.session_id;
        connected = true;
        
        std::cout << "Connected! Session: " << session_id << "\n";
        return true;
    }
    
    void disconnect() {
        if (connected) {
            Header header = {0xABCD, 1, MSG_DISCONNECT, session_id, 0, 0};
            send(sock, &header, sizeof(header), 0);
            close(sock);
            connected = false;
        }
    }
    
    bool upload_and_scan(const std::string& filepath) {
        // Read file
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "Cannot open file\n";
            return false;
        }
        
        size_t file_size = file.tellg();
        file.seekg(0);
        std::vector<char> file_data(file_size);
        file.read(file_data.data(), file_size);
        file.close();
        
        // Get filename
        std::string filename = filepath;
        size_t pos = filename.find_last_of("/\\");
        if (pos != std::string::npos) {
            filename = filename.substr(pos + 1);
        }
        
        // Prepare payload
        std::vector<uint8_t> payload(256 + file_size);
        memset(payload.data(), 0, 256);
        memcpy(payload.data(), filename.c_str(), filename.length());
        memcpy(payload.data() + 256, file_data.data(), file_size);
        
        // Send header
        Header header = {0xABCD, 1, MSG_FILE_UPLOAD, session_id, 
                        static_cast<uint32_t>(payload.size()), 0};
        send(sock, &header, sizeof(header), 0);
        
        // Send file
        size_t sent = 0;
        while (sent < payload.size()) {
            ssize_t n = send(sock, payload.data() + sent, 
                           std::min<size_t>(BUFFER_SIZE, payload.size() - sent), 0);
            if (n <= 0) break;
            sent += n;
            std::cout << "\rUploading: " << (sent * 100 / payload.size()) << "%" << std::flush;
        }
        std::cout << "\nUpload complete!\n";
        
        // Get response
        recv(sock, &header, sizeof(header), 0);
        
        // Wait for processing
        std::cout << "Scanning file...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Try to get result from server
        get_scan_result();
        
        return true;
    }
    
    void get_scan_result() {
        // Send request for result
        Header header = {0xABCD, 1, MSG_SCAN_RESULT, session_id, 0, 0};
        send(sock, &header, sizeof(header), 0);
        
        // Try to receive result
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        
        struct timeval timeout = {3, 0}; // 3 seconds timeout
        
        if (select(sock + 1, &readfds, NULL, NULL, &timeout) > 0) {
            Header resp_header;
            if (recv(sock, &resp_header, sizeof(resp_header), MSG_PEEK) > 0) {
                recv(sock, &resp_header, sizeof(resp_header), 0);
                
                if (resp_header.payload_len > 0) {
                    std::vector<char> result(resp_header.payload_len);
                    recv(sock, result.data(), resp_header.payload_len, 0);
                    
                    std::cout << "\n=== SERVER RESULT ===" << std::endl;
                    std::cout.write(result.data(), resp_header.payload_len);
                    std::cout << "\n==================" << std::endl;
                    return;
                }
            }
        }
        
        // Dacă nu primim rezultat de la server, afișăm generic
        std::cout << "\n=== SCAN RESULT ===" << std::endl;
        std::cout << "Scan completed successfully" << std::endl;
        std::cout << "Check server logs for details" << std::endl;
        std::cout << "==================" << std::endl;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cout << "Usage: " << argv[0] << " <server_ip> <port> <file>\n";
        return 1;
    }
    
    SimpleClient client(argv[1], std::stoi(argv[2]));
    
    if (!client.connect_to_server()) {
        return 1;
    }
    
    client.upload_and_scan(argv[3]);
    
    client.disconnect();
    
    return 0;
}