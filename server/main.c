// main.c - Server Principal Antivirus
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/inotify.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <semaphore.h>
#include <clamav.h>

#ifndef CL_SCAN_STDOPT
#define CL_SCAN_STDOPT CL_SCAN_ALLMATCH
#endif

#define UNIX_SOCKET_PATH "/tmp/antivirus_admin.sock"
#define INET_PORT 8080
#define MAX_CLIENTS 100
#define BUFFER_SIZE 4096
#define QUEUE_SIZE 1000
#define PROCESSING_DIR "/tmp/antivirus/processing/"
#define OUTGOING_DIR "/tmp/antivirus/outgoing/"

// Structuri de date
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
} log_level_t;

typedef enum {
    MSG_CONNECT = 0x01,
    MSG_FILE_UPLOAD = 0x02,
    MSG_SCAN_STATUS = 0x03,
    MSG_SCAN_RESULT = 0x04,
    MSG_DISCONNECT = 0x05,
    MSG_NOTIFY = 0x06
} msg_type_t;

typedef struct {
    uint16_t magic;
    uint16_t version;
    uint32_t msg_type;
    uint32_t session_id;
    uint32_t payload_len;
    uint8_t encrypted;
    uint8_t reserved[3];
} message_header_t;

typedef struct {
    char filename[256];
    char client_ip[INET_ADDRSTRLEN];
    uint32_t session_id;
    time_t timestamp;
    int status; // 0=pending, 1=processing, 2=completed
    int result; // 0=clean, 1=infected, 2=error
    char virus_name[256];
} scan_job_t;

typedef struct {
    scan_job_t jobs[QUEUE_SIZE];
    int front;
    int rear;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} job_queue_t;

typedef struct {
    int socket;
    char ip[INET_ADDRSTRLEN];
    time_t connect_time;
    uint32_t session_id;
    int active;
} client_info_t;

// Variabile globale
log_level_t current_log_level = LOG_INFO;
job_queue_t job_queue;
client_info_t clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
int server_running = 1;
int admin_socket = -1;
int inet_socket = -1;
struct cl_engine *clamav_engine = NULL;
int inotify_fd = -1;
int inotify_wd = -1;

// Thread-uri
pthread_t admin_thread;
pthread_t inet_thread;
pthread_t rest_thread;
pthread_t processor_thread;
pthread_t inotify_thread;

// Pipe pentru comunicare internă
int internal_pipe[2];

// Funcții de logging
void log_message(log_level_t level, const char *format, ...) {
    if (level < current_log_level) return;
    
    pthread_mutex_lock(&log_mutex);
    
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    const char *level_str[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
    printf("[%s] [%s] ", timestamp, level_str[level]);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
    
    pthread_mutex_unlock(&log_mutex);
}

// Inițializare coadă
void init_queue() {
    job_queue.front = 0;
    job_queue.rear = 0;
    job_queue.count = 0;
    pthread_mutex_init(&job_queue.mutex, NULL);
    pthread_cond_init(&job_queue.not_empty, NULL);
    pthread_cond_init(&job_queue.not_full, NULL);
}

// Adăugare job în coadă
int enqueue_job(scan_job_t *job) {
    pthread_mutex_lock(&job_queue.mutex);
    
    while (job_queue.count == QUEUE_SIZE) {
        pthread_cond_wait(&job_queue.not_full, &job_queue.mutex);
    }
    
    memcpy(&job_queue.jobs[job_queue.rear], job, sizeof(scan_job_t));
    job_queue.rear = (job_queue.rear + 1) % QUEUE_SIZE;
    job_queue.count++;
    
    pthread_cond_signal(&job_queue.not_empty);
    pthread_mutex_unlock(&job_queue.mutex);
    
    log_message(LOG_INFO, "Job enqueued: %s from %s", job->filename, job->client_ip);
    return 0;
}

// Extragere job din coadă
int dequeue_job(scan_job_t *job) {
    pthread_mutex_lock(&job_queue.mutex);
    
    while (job_queue.count == 0 && server_running) {
        pthread_cond_wait(&job_queue.not_empty, &job_queue.mutex);
    }
    
    if (!server_running && job_queue.count == 0) {
        pthread_mutex_unlock(&job_queue.mutex);
        return -1;
    }
    
    memcpy(job, &job_queue.jobs[job_queue.front], sizeof(scan_job_t));
    job_queue.front = (job_queue.front + 1) % QUEUE_SIZE;
    job_queue.count--;
    
    pthread_cond_signal(&job_queue.not_full);
    pthread_mutex_unlock(&job_queue.mutex);
    
    return 0;
}

int init_clamav() {
    // Verifică dacă clamscan e disponibil
    if (system("which clamscan > /dev/null 2>&1") != 0) {
        log_message(LOG_WARNING, "ClamAV not installed, using pattern matching");
        return 0; // Nu e eroare fatală
    }
    
    log_message(LOG_INFO, "ClamAV scanner available");
    return 0;
}
// Scanare fișier cu ClamAV
int scan_file_clamav(const char *filepath, char *virus_name) {
    char command[1024];
    char result[256];
    FILE *fp;
    
    // Construiește comanda clamscan
    snprintf(command, sizeof(command), "clamscan --no-summary --stdout %s 2>&1", filepath);
    
    log_message(LOG_DEBUG, "Running: %s", command);
    
    // Execută clamscan
    fp = popen(command, "r");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to run clamscan");
        // Fallback la EICAR simplu
        FILE *file = fopen(filepath, "r");
        if (file) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), file)) {
                if (strstr(buffer, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
                    strcpy(virus_name, "EICAR-Test-Signature");
                    fclose(file);
                    return 1;
                }
            }
            fclose(file);
        }
        return 0;
    }
    
    // Citește rezultatul
    int infected = 0;
    while (fgets(result, sizeof(result), fp) != NULL) {
        // ClamAV format: filename: virus_name FOUND
        if (strstr(result, "FOUND")) {
            infected = 1;
            
            // Extrage numele virusului
            char *start = strchr(result, ':');
            if (start) {
                start += 2; // Skip ": "
                char *end = strstr(start, " FOUND");
                if (end) {
                    *end = '\0';
                    strncpy(virus_name, start, 255);
                    virus_name[255] = '\0';
                }
            }
            
            log_message(LOG_WARNING, "ClamAV detected: %s", virus_name);
        }
    }
    
    pclose(fp);
    
    if (!infected) {
        log_message(LOG_INFO, "ClamAV: File %s is clean", filepath);
    }
    
    return infected;
}

// Thread processor
void *processor_thread_func(void *arg) {
    scan_job_t job;
    char filepath[512];
    
    log_message(LOG_INFO, "Processor thread started");
    
    while (server_running) {
        if (dequeue_job(&job) == 0) {
            job.status = 1; // Processing
            
            snprintf(filepath, sizeof(filepath), "%s%s", PROCESSING_DIR, job.filename);
            
            // Scanare ClamAV
            int clamav_result = scan_file_clamav(filepath, job.virus_name);
            
            if (clamav_result >= 0) {
                job.result = clamav_result;
                job.status = 2; // Completed
                
                // Notificare prin pipe
                write(internal_pipe[1], &job.session_id, sizeof(uint32_t));
            } else {
                job.result = 2; // Error
                job.status = 2;
            }
            
            // Mutare fișier în outgoing
            char outpath[512];
            snprintf(outpath, sizeof(outpath), "%s%s", OUTGOING_DIR, job.filename);
            rename(filepath, outpath);
        }
    }
    
    log_message(LOG_INFO, "Processor thread stopped");
    return NULL;
}

// Thread admin
void *admin_thread_func(void *arg) {
    struct sockaddr_un addr;
    int admin_client = -1;
    fd_set readfds;
    struct timeval timeout;
    time_t last_activity = time(NULL);
    
    log_message(LOG_INFO, "Admin thread started");
    
    // Creare UNIX socket
    admin_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (admin_socket < 0) {
        log_message(LOG_ERROR, "Failed to create admin socket");
        return NULL;
    }
    
    unlink(UNIX_SOCKET_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UNIX_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (bind(admin_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message(LOG_ERROR, "Failed to bind admin socket");
        close(admin_socket);
        return NULL;
    }
    
    listen(admin_socket, 1);
    
    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(admin_socket, &readfds);
        int max_fd = admin_socket;
        
        if (admin_client >= 0) {
            FD_SET(admin_client, &readfds);
            if (admin_client > max_fd) max_fd = admin_client;
        }
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            log_message(LOG_ERROR, "Select error in admin thread");
            break;
        }
        
        // Verificare timeout admin
        if (admin_client >= 0 && time(NULL) - last_activity > 300) {
            log_message(LOG_INFO, "Admin client timeout");
            close(admin_client);
            admin_client = -1;
        }
        
        // Conexiune nouă
        if (FD_ISSET(admin_socket, &readfds)) {
            int new_client = accept(admin_socket, NULL, NULL);
            if (new_client >= 0) {
                if (admin_client >= 0) {
                    const char *msg = "ERR: Admin already connected\n";
                    send(new_client, msg, strlen(msg), 0);
                    close(new_client);
                } else {
                    admin_client = new_client;
                    last_activity = time(NULL);
                    const char *msg = "OK: Admin connected\n";
                    send(admin_client, msg, strlen(msg), 0);
                    log_message(LOG_INFO, "Admin client connected");
                }
            }
        }
        
        // Date de la admin
        if (admin_client >= 0 && FD_ISSET(admin_client, &readfds)) {
            char buffer[BUFFER_SIZE];
            int bytes = recv(admin_client, buffer, sizeof(buffer) - 1, 0);
            
            if (bytes > 0) {
                buffer[bytes] = '\0';
                last_activity = time(NULL);
                
                // Procesare comenzi admin
                if (strncmp(buffer, "SET_LOG_LEVEL", 13) == 0) {
                    char level[16];
                    sscanf(buffer, "SET_LOG_LEVEL %s", level);
                    
                    if (strcmp(level, "DEBUG") == 0) current_log_level = LOG_DEBUG;
                    else if (strcmp(level, "INFO") == 0) current_log_level = LOG_INFO;
                    else if (strcmp(level, "WARNING") == 0) current_log_level = LOG_WARNING;
                    else if (strcmp(level, "ERROR") == 0) current_log_level = LOG_ERROR;
                    
                    char response[128];
                    snprintf(response, sizeof(response), "OK: Log level set to %s\n", level);
                    send(admin_client, response, strlen(response), 0);
                }
                else if (strncmp(buffer, "LIST_CLIENTS", 12) == 0) {
                    pthread_mutex_lock(&clients_mutex);
                    char response[4096] = "Active clients:\n";
                    
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (clients[i].active) {
                            char client_info[256];
                            snprintf(client_info, sizeof(client_info), 
                                    "- %s (session: %u, connected: %ld sec ago)\n",
                                    clients[i].ip, clients[i].session_id,
                                    time(NULL) - clients[i].connect_time);
                            strcat(response, client_info);
                        }
                    }
                    
                    pthread_mutex_unlock(&clients_mutex);
                    send(admin_client, response, strlen(response), 0);
                }
                else if (strncmp(buffer, "DISCONNECT_IP", 13) == 0) {
                    char ip[INET_ADDRSTRLEN];
                    sscanf(buffer, "DISCONNECT_IP %s", ip);
                    
                    pthread_mutex_lock(&clients_mutex);
                    int disconnected = 0;
                    
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (clients[i].active && strcmp(clients[i].ip, ip) == 0) {
                            close(clients[i].socket);
                            clients[i].active = 0;
                            disconnected++;
                        }
                    }
                    
                    pthread_mutex_unlock(&clients_mutex);
                    
                    char response[128];
                    snprintf(response, sizeof(response), 
                            "OK: Disconnected %d clients from %s\n", disconnected, ip);
                    send(admin_client, response, strlen(response), 0);
                }
                else if (strncmp(buffer, "QUEUE_STATUS", 12) == 0) {
                    pthread_mutex_lock(&job_queue.mutex);
                    char response[256];
                    snprintf(response, sizeof(response), 
                            "Queue status: %d jobs pending\n", job_queue.count);
                    pthread_mutex_unlock(&job_queue.mutex);
                    send(admin_client, response, strlen(response), 0);
                }
            } else {
                log_message(LOG_INFO, "Admin client disconnected");
                close(admin_client);
                admin_client = -1;
            }
        }
    }
    
    if (admin_client >= 0) close(admin_client);
    close(admin_socket);
    unlink(UNIX_SOCKET_PATH);
    
    log_message(LOG_INFO, "Admin thread stopped");
    return NULL;
}

// Thread INET pentru clienți
void *inet_thread_func(void *arg) {
    struct sockaddr_in addr;
    fd_set readfds;
    
    log_message(LOG_INFO, "INET thread started");
    
    // Creare TCP socket
    inet_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (inet_socket < 0) {
        log_message(LOG_ERROR, "Failed to create INET socket");
        return NULL;
    }
    
    int opt = 1;
    setsockopt(inet_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(INET_PORT);
    
    if (bind(inet_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message(LOG_ERROR, "Failed to bind INET socket");
        close(inet_socket);
        return NULL;
    }
    
    listen(inet_socket, 10);
    log_message(LOG_INFO, "Server listening on port %d", INET_PORT);
    
    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(inet_socket, &readfds);
        int max_fd = inet_socket;
        
        // Adaugă clienții activi
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active) {
                FD_SET(clients[i].socket, &readfds);
                if (clients[i].socket > max_fd) max_fd = clients[i].socket;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        
        struct timeval timeout = {1, 0};
        int activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            log_message(LOG_ERROR, "Select error in INET thread");
            break;
        }
        
        // Conexiune nouă
        if (FD_ISSET(inet_socket, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int new_client = accept(inet_socket, (struct sockaddr*)&client_addr, &client_len);
            
            if (new_client >= 0) {
                pthread_mutex_lock(&clients_mutex);
                int slot = -1;
                
                // Găsește slot liber
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (!clients[i].active) {
                        slot = i;
                        break;
                    }
                }
                
                if (slot >= 0) {
                    clients[slot].socket = new_client;
                    clients[slot].active = 1;
                    clients[slot].connect_time = time(NULL);
                    clients[slot].session_id = (uint32_t)time(NULL) ^ (uint32_t)new_client;
                    inet_ntop(AF_INET, &client_addr.sin_addr, clients[slot].ip, INET_ADDRSTRLEN);
                    
                    log_message(LOG_INFO, "Client connected from %s (session: %u)", 
                               clients[slot].ip, clients[slot].session_id);
                    
                    // Trimite session ID
                    message_header_t header = {
                        .magic = 0xABCD,
                        .version = 0x0001,
                        .msg_type = MSG_CONNECT,
                        .session_id = clients[slot].session_id,
                        .payload_len = 0,
                        .encrypted = 0
                    };
                    send(new_client, &header, sizeof(header), 0);
                } else {
                    log_message(LOG_WARNING, "Max clients reached, rejecting connection");
                    close(new_client);
                }
                
                pthread_mutex_unlock(&clients_mutex);
            }
        }
        
        // Date de la clienți
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && FD_ISSET(clients[i].socket, &readfds)) {
                message_header_t header;
                int bytes = recv(clients[i].socket, &header, sizeof(header), MSG_PEEK);
                
                if (bytes == sizeof(header) && header.magic == 0xABCD) {
                    recv(clients[i].socket, &header, sizeof(header), 0);
                    
                    switch (header.msg_type) {
                        case MSG_FILE_UPLOAD: {
                            char *payload = malloc(header.payload_len);
                            recv(clients[i].socket, payload, header.payload_len, 0);
                            
                            // Procesare upload fișier
                            scan_job_t job;
                            memset(&job, 0, sizeof(job));
                            
                            // Extrage numele fișierului din payload
                            strncpy(job.filename, payload, 255);
                            job.filename[255] = '\0';
                            
                            // Salvare fișier
                            char filepath[512];
                            snprintf(filepath, sizeof(filepath), "%s%s", PROCESSING_DIR, job.filename);
                            
                            FILE *fp = fopen(filepath, "wb");
                            if (fp) {
                                fwrite(payload + 256, 1, header.payload_len - 256, fp);
                                fclose(fp);
                                
                                // Adaugă în coadă
                                strncpy(job.client_ip, clients[i].ip, INET_ADDRSTRLEN);
                                job.session_id = header.session_id;
                                job.timestamp = time(NULL);
                                job.status = 0;
                                
                                enqueue_job(&job);
                                
                                // Răspuns
                                header.msg_type = MSG_SCAN_STATUS;
                                header.payload_len = 0;
                                send(clients[i].socket, &header, sizeof(header), 0);
                            }
                            
                            free(payload);
                            break;
                        }
                        
                        case MSG_SCAN_STATUS: {
                            // Verifică status scanare
                            pthread_mutex_lock(&job_queue.mutex);
                            int position = -1;
                            
                            for (int j = 0; j < job_queue.count; j++) {
                                int idx = (job_queue.front + j) % QUEUE_SIZE;
                                if (job_queue.jobs[idx].session_id == header.session_id) {
                                    position = j;
                                    break;
                                }
                            }
                            
                            pthread_mutex_unlock(&job_queue.mutex);
                            
                            header.payload_len = sizeof(int);
                            send(clients[i].socket, &header, sizeof(header), 0);
                            send(clients[i].socket, &position, sizeof(int), 0);
                            break;
                        }
                        
                        case MSG_DISCONNECT: {
                            log_message(LOG_INFO, "Client %s disconnecting", clients[i].ip);
                            close(clients[i].socket);
                            clients[i].active = 0;
                            break;
                        }
                    }
                } else if (bytes <= 0) {
                    // Client deconectat
                    log_message(LOG_INFO, "Client %s disconnected", clients[i].ip);
                    close(clients[i].socket);
                    clients[i].active = 0;
                }
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }
    
    close(inet_socket);
    log_message(LOG_INFO, "INET thread stopped");
    return NULL;
}

// Thread inotify
void *inotify_thread_func(void *arg) {
    char buffer[4096];
    
    log_message(LOG_INFO, "Inotify thread started");
    
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        log_message(LOG_ERROR, "Failed to initialize inotify");
        return NULL;
    }
    
    inotify_wd = inotify_add_watch(inotify_fd, OUTGOING_DIR, IN_MOVED_TO | IN_CLOSE_WRITE);
    if (inotify_wd < 0) {
        log_message(LOG_ERROR, "Failed to add inotify watch");
        close(inotify_fd);
        return NULL;
    }
    
    while (server_running) {
        int length = read(inotify_fd, buffer, sizeof(buffer));
        
        if (length < 0) {
            if (errno != EINTR) {
                log_message(LOG_ERROR, "Inotify read error");
                break;
            }
            continue;
        }
        
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event*)&buffer[i];
            
            if (event->mask & (IN_MOVED_TO | IN_CLOSE_WRITE)) {
                log_message(LOG_INFO, "File ready for delivery: %s", event->name);
                
                // Notificare client prin găsirea sesiunii
                // Implementare notificare asincronă
            }
            
            i += sizeof(struct inotify_event) + event->len;
        }
    }
    
    inotify_rm_watch(inotify_fd, inotify_wd);
    close(inotify_fd);
    
    log_message(LOG_INFO, "Inotify thread stopped");
    return NULL;
}

// Thread REST API
void *rest_thread_func(void *arg) {
    // Implementare simplificată REST API
    log_message(LOG_INFO, "REST API thread started");
    
    // TODO: Implementare HTTP server minimal pentru REST API
    
    log_message(LOG_INFO, "REST API thread stopped");
    return NULL;
}

// Handler semnale
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message(LOG_INFO, "Received shutdown signal");
        server_running = 0;
        
        // Trezește thread-urile blocate
        pthread_cond_broadcast(&job_queue.not_empty);
    }
}

// Inițializare directoare
void init_directories() {
    system("mkdir -p /tmp/antivirus/processing");
    system("mkdir -p /tmp/antivirus/outgoing");
}

// Main
int main(int argc, char *argv[]) {
    // Parsare argumente
    int opt;
    while ((opt = getopt(argc, argv, "p:l:")) != -1) {
        switch (opt) {
            case 'p':
                // Port custom
                break;
            case 'l':
                if (strcmp(optarg, "DEBUG") == 0) current_log_level = LOG_DEBUG;
                else if (strcmp(optarg, "INFO") == 0) current_log_level = LOG_INFO;
                else if (strcmp(optarg, "WARNING") == 0) current_log_level = LOG_WARNING;
                else if (strcmp(optarg, "ERROR") == 0) current_log_level = LOG_ERROR;
                break;
        }
    }
    
    log_message(LOG_INFO, "Antivirus server starting...");
    
    // Inițializări
    init_directories();
    init_queue();
    
    if (pipe(internal_pipe) < 0) {
        log_message(LOG_ERROR, "Failed to create internal pipe");
        return 1;
    }
    /*
    if (init_clamav() < 0) {
        log_message(LOG_ERROR, "Failed to initialize ClamAV");
        return 1;
    }
    */
    log_message(LOG_INFO, "Using simplified virus detection (EICAR-only)");
    // Setare handler semnale
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // Blocare semnale pentru thread-uri
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    // Pornire thread-uri
    pthread_create(&admin_thread, NULL, admin_thread_func, NULL);
    pthread_create(&inet_thread, NULL, inet_thread_func, NULL);
    pthread_create(&processor_thread, NULL, processor_thread_func, NULL);
    pthread_create(&inotify_thread, NULL, inotify_thread_func, NULL);
    pthread_create(&rest_thread, NULL, rest_thread_func, NULL);
    
    // Thread principal - deblochează semnalele
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    
    // Așteaptă semnale și coordonează
    while (server_running) {
        uint32_t completed_session;
        if (read(internal_pipe[0], &completed_session, sizeof(uint32_t)) > 0) {
            log_message(LOG_DEBUG, "Job completed for session %u", completed_session);
            
            // Notificare client (implementare notificare asincronă)
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active && clients[i].session_id == completed_session) {
                    message_header_t notify = {
                        .magic = 0xABCD,
                        .version = 0x0001,
                        .msg_type = MSG_NOTIFY,
                        .session_id = completed_session,
                        .payload_len = 0,
                        .encrypted = 0
                    };
                    send(clients[i].socket, &notify, sizeof(notify), MSG_NOSIGNAL);
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
        }
        
        sleep(1);
    }
    
    // Așteaptă thread-uri
    pthread_join(admin_thread, NULL);
    pthread_join(inet_thread, NULL);
    pthread_join(processor_thread, NULL);
    pthread_join(inotify_thread, NULL);
    pthread_join(rest_thread, NULL);
    
    // Cleanup
    /*
    if (clamav_engine) {
        cl_engine_free(clamav_engine);
    }
    */
    close(internal_pipe[0]);
    close(internal_pipe[1]);
    
    log_message(LOG_INFO, "Server shutdown complete");
    return 0;
}