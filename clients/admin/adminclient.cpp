// admin_client.cpp - Client Administrator pentru Server Antivirus
#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>

#define UNIX_SOCKET_PATH "/tmp/antivirus_admin.sock"
#define BUFFER_SIZE 4096

class AdminClient {
private:
    int socket_fd;
    bool connected;
    std::string prompt;
    
public:
    AdminClient() : socket_fd(-1), connected(false), prompt("antivirus-admin> ") {}
    
    ~AdminClient() {
        disconnect();
    }
    
    bool connect_to_server() {
        socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }
        
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, UNIX_SOCKET_PATH, sizeof(addr.sun_path) - 1);
        
        if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Failed to connect to server. Is the server running?" << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
        
        // Citește răspunsul inițial
        char buffer[BUFFER_SIZE];
        int bytes = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::cout << "Server: " << buffer;
            if (strstr(buffer, "OK:") != nullptr) {
                connected = true;
                return true;
            }
        }
        
        close(socket_fd);
        socket_fd = -1;
        return false;
    }
    
    void disconnect() {
        if (socket_fd >= 0) {
            close(socket_fd);
            socket_fd = -1;
            connected = false;
        }
    }
    
    bool send_command(const std::string& command) {
        if (!connected) {
            std::cerr << "Not connected to server" << std::endl;
            return false;
        }
        
        if (send(socket_fd, command.c_str(), command.length(), 0) < 0) {
            std::cerr << "Failed to send command" << std::endl;
            return false;
        }
        
        char buffer[BUFFER_SIZE];
        int bytes = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::cout << buffer;
            return true;
        } else if (bytes == 0) {
            std::cerr << "Server disconnected" << std::endl;
            connected = false;
        }
        
        return false;
    }
    
    void print_help() {
        std::cout << "\nAvailable commands:\n"
                  << "  help                    - Show this help message\n"
                  << "  set_log_level <level>   - Set log level (DEBUG/INFO/WARNING/ERROR)\n"
                  << "  list_clients            - List all connected clients\n"
                  << "  disconnect_ip <ip>      - Disconnect all clients from specified IP\n"
                  << "  queue_status            - Show queue status\n"
                  << "  stats                   - Show server statistics\n"
                  << "  clear                   - Clear screen\n"
                  << "  exit/quit               - Exit admin client\n\n";
    }
    
    void clear_screen() {
        std::cout << "\033[2J\033[1;1H";
    }
    
    void print_banner() {
        std::cout << "\n"
                  << "╔═══════════════════════════════════════════════════════╗\n"
                  << "║         Antivirus Server Admin Console v1.0           ║\n"
                  << "║                                                       ║\n"
                  << "║  Type 'help' for available commands                  ║\n"
                  << "╚═══════════════════════════════════════════════════════╝\n\n";
    }
    
    void run() {
        print_banner();
        
        if (!connect_to_server()) {
            return;
        }
        
        std::string line;
        while (connected) {
            std::cout << prompt;
            if (!std::getline(std::cin, line)) {
                break;
            }
            
            // Trim whitespace
            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);
            
            if (line.empty()) {
                continue;
            }
            
            // Parse command
            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd;
            
            // Convert to lowercase
            std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
            
            if (cmd == "help") {
                print_help();
            } else if (cmd == "clear") {
                clear_screen();
                print_banner();
            } else if (cmd == "exit" || cmd == "quit") {
                std::cout << "Disconnecting from server...\n";
                break;
            } else if (cmd == "set_log_level") {
                std::string level;
                iss >> level;
                if (level.empty()) {
                    std::cerr << "Usage: set_log_level <DEBUG|INFO|WARNING|ERROR>\n";
                } else {
                    std::transform(level.begin(), level.end(), level.begin(), ::toupper);
                    send_command("SET_LOG_LEVEL " + level);
                }
            } else if (cmd == "list_clients") {
                send_command("LIST_CLIENTS");
            } else if (cmd == "disconnect_ip") {
                std::string ip;
                iss >> ip;
                if (ip.empty()) {
                    std::cerr << "Usage: disconnect_ip <ip_address>\n";
                } else {
                    send_command("DISCONNECT_IP " + ip);
                }
            } else if (cmd == "queue_status") {
                send_command("QUEUE_STATUS");
            } else if (cmd == "stats") {
                // Implementare statistici extinse
                send_command("STATS");
            } else {
                std::cerr << "Unknown command: " << cmd << "\n";
                std::cerr << "Type 'help' for available commands\n";
            }
        }
        
        disconnect();
    }
};

// Funcție pentru a ascunde/afișa parola
void set_echo(bool enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (enable) {
        tty.c_lflag |= ECHO;
    } else {
        tty.c_lflag &= ~ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

int main(int argc, char* argv[]) {
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        std::cout << "Usage: " << argv[0] << " [socket_path]\n";
        std::cout << "Default socket path: " << UNIX_SOCKET_PATH << "\n";
        return 0;
    }
    
    // Verificare permisiuni (trebuie să ruleze local)
    if (access(UNIX_SOCKET_PATH, F_OK) == 0) {
        if (access(UNIX_SOCKET_PATH, R_OK | W_OK) != 0) {
            std::cerr << "Error: Insufficient permissions to access admin socket\n";
            std::cerr << "This client must run on the same machine as the server\n";
            return 1;
        }
    }
    
    AdminClient client;
    
    try {
        client.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}