#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <termios.h>

struct server_state {
    int fd;
    char last_result;
    char last_line[256];
};

static bool debug = false;

static int readcmd(int fd, char *buf, int maxlen)
{
    char *p = buf;
    int len;

    maxlen--; 
    while((len = recv(fd, p, 1, 0))> 0) {
        if(!*(p++)) return(p-buf);
        if((p-buf)>=maxlen) break;
    }
    *(p++)='\0'; /* Always null terminate even on failure */
    if(len <0) return -1;
    else return(p-buf);
}

bool server_read(server_state *state) 
{
    char line[sizeof(state->last_line)+1];
    int l;

    l = readcmd(state->fd, line, sizeof(line));
    if(l<1) return false;
    state->last_result = line[0];
    strncpy(state->last_line, line+1, sizeof(state->last_line));
    if(debug) fprintf(stderr,"%s\n", line);
    return true;
}

bool server_send(server_state *state, const char *line) 
{
    int l;

    l=send(state->fd, line, strlen(line)+1, 0);
    if(debug) fprintf(stderr,"%s\n", line);
    return l>0;
}

bool server_cmd(server_state *state, const char *cmd, ...)
{
    char line[256];
    va_list vargs;

    va_start (vargs, cmd);
    vsnprintf(line, sizeof(line), cmd, vargs);
    va_end(vargs);
    if(!server_send(state, line)) 
        return false;
    if(!server_read(state))
        return false;
    if(state->last_result == '-') {
        fprintf(stderr,"Error: %s\n", state->last_line);
    }
    return true;
}

void handle_ls(struct server_state *state, const char *args)
{
    if(server_cmd(state, "LIST F %s", args))
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_get(struct server_state *state, const char *args)
{
    const char *filename = basename(args);

    if(!server_cmd(state, "RETR %s", args))
        return;
    long length = strtoul(state->last_line, NULL, 10);
    void *buf = malloc(length);
    if(!buf) {
        fprintf(stderr, "Couldn't allocate memory: %s", filename, strerror(errno));
        server_cmd(state, "STOP");
        return;
    }
    FILE *f = fopen(filename, "w");
    if(!f) {
        fprintf(stderr, "Couldn't create %s: %s", filename, strerror(errno));
        server_cmd(state, "STOP");
        free(buf);
        return;
    }
    
    server_send(state, "SEND"); 
    length = recv(state->fd, buf, length, 0);
    if(length < 1) {
        fprintf(stderr, "Couldn't read file: %s", strerror(errno));
        free(buf);
        return;
    }
    fwrite(buf, length, 1, f);
    fclose(f);
    free(buf);
    printf("Read %ld bytes into %s\n",length, filename);
}

void handle_put(struct server_state *state, const char *args)
{

}

void handle_rename(struct server_state *state, const char *args)
{

}

void handle_remove(struct server_state *state, const char *args)
{
    if(server_cmd(state, "KILL %s", args))
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_cd(struct server_state *state, const char *args)
{
    if(server_cmd(state, "CDIR %s", args))
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_type(struct server_state *state, const char *args)
{
    if(!args) args="b";
    char c=tolower(args[0]);
    if((c!='a' && c!='b' && c!='c')||args[1]) {
        fprintf(stderr,"Usage: type {a|b|c}\n");
        return;
    }
    if(server_cmd(state, "TYPE %c", c))
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_help()
{
    fprintf(stderr, "Insert help here\n");
}

bool parse_line(struct server_state *state, const char *cmd, const char *args)
{
    if(!strcasecmp(cmd, "quit") || !strcasecmp(cmd, "exit"))
        return false;

    if(!*cmd)
        return true;

    if(!strcasecmp(cmd, "ls")) handle_ls(state, args);
    else if(!strcasecmp(cmd, "get")) handle_get(state, args);
    else if(!strcasecmp(cmd, "put")) handle_put(state, args);
    else if(!strcasecmp(cmd, "mv")) handle_rename(state, args);
    else if(!strcasecmp(cmd, "rm")) handle_remove(state, args);
    else if(!strcasecmp(cmd, "cd")) handle_cd(state, args);
    else if(!strcasecmp(cmd, "type")) handle_type(state, args);
    else if(!strcasecmp(cmd, "help")) handle_help();
    else if(!strcasecmp(cmd, "?")) handle_help();
    else printf("Invalid command %s\n", cmd);
    return true;
}

void read_commands(int server_fd)
{
    struct server_state state = {0};

    state.fd = server_fd;

    while(true) {
        char *line = readline("sftp> ");

        if(!line) break;
        if(*line) add_history(line);

        char *args = strchr(line, ' ');
        const char *cmd = line;
        if(args) *(args++)='\0';
        if(!parse_line(&state, cmd, args)) break;

        free(line);
    }
}

int echo_set(bool on)
{
    struct termios flags;

    if (tcgetattr (0, &flags) != 0)
        return -1;
    if(on) flags.c_lflag |= ECHO;
    else flags.c_lflag &= ~ECHO;
    if (tcsetattr (0, TCSAFLUSH, &flags) != 0)
        return -1;
    return 0;
}

bool login(struct server_state *state, const char *username, const char *password)
{
    const char *alloc_username = NULL;
    const char *alloc_password = NULL;
    bool result = false;

    if(!server_read(state)) {
        fprintf(stderr, "Server connection lost\n");
        goto exit;
    }
    if(state->last_result != '+') {
        fprintf(stderr, "Server not available: %s\n", state->last_line);
        goto exit;
    }

    if(!username) {
        alloc_username=readline("Username: ");
        if(!alloc_username) {
            fprintf(stderr, "Aborted\n");
            return -1;
        }
        username = alloc_username;
    }

    if(!password) {
        echo_set(false);
        alloc_password=readline("Password: ");
        echo_set(true);
        if(!alloc_password) {
            fprintf(stderr, "Aborted\n");
            return -1;
        }
        password=alloc_password;
    }

    if(!server_cmd(state, "USER %s", username) || state->last_result != '+')  {
        goto exit;
    }

    if(!server_cmd(state, "PASS %s", password) || state->last_result !='!') {
        goto exit;
    }

    result = true;

exit:
    free((void*)alloc_username);
    free((void*)alloc_password);

    return result;
}

int connect_server(const char *server, const char *username, const char *password)
{
    int result;
    struct addrinfo hints = {0}, *info, *p;
    struct server_state state = {0};

    hints.ai_socktype = SOCK_STREAM;
    if((result=getaddrinfo(server, "115", &hints, &info)) != 0) {
        fprintf(stderr,"Unable to connect: %s\n",gai_strerror(result));
        return -1;
    }
    
    for(p=info; p; p=p->ai_next) {
        if((state.fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) > 0) {
            if(connect(state.fd, p->ai_addr, p->ai_addrlen) == 0)
                break; 
            result = errno;
            close(state.fd);
        }
    }

    if(!p) {
        fprintf(stderr,"Unable to connect: %s\n",strerror(result));
        return -1;
    }

    if(!login(&state, username, password)) {
        close(state.fd);
        return -1;
    }

    printf("Connected to %s\n", server);
    return state.fd;
}


void usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s [--user=<username>][--password=<password>][-u username][-p password] <server>\n", cmd);
}

int main(int argc, char **argv)
{
    const char *username = NULL;
    const char *password = NULL;
    const char *server = NULL;

    static struct option long_options[] =
    {
        {"user",     required_argument,   0, 'u'},
        {"password", required_argument,   0, 'p'},
        {"debug",    no_argument,         0, 'd'},
        {0}
    };

    while(true) {
        /* getopt_long stores the option index here. */
        int option_index = 0;

        int c = getopt_long (argc, argv, "u:p:d",
                        long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;
        switch(c) {
            case 'u': username = optarg; break;
            case 'p': password = optarg; break;
            case 'd': debug = true; break;
            case 'h':
            case ':':
            case '?': usage(argv[0]); return 0;
            default: abort();
        }
    }

    if(optind != argc-1) {
        usage(argv[0]);
        return 0;
    }

    server = argv[optind];

    int fd = connect_server(server, username, password); 
    if(fd<0) {
        return -1;
    }

    read_commands(fd);
    return 0;
}