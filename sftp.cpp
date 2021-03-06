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
#include "buffer.h"

struct server_state {
    int fd;
    char last_result;
    char *last_line;
    int buf_len;
    char *buf;
    socketbuffer *buffer;

    server_state(int socket);
    ~server_state();
};

static bool debug = false;

server_state::server_state(int socket)
{
    fd = socket;
    last_result = 0;
    last_line = NULL;
    buf = (char*)malloc(BUFSIZ);
    buf_len = BUFSIZ;
    buffer = new socketbuffer(socket);
}

server_state::~server_state() 
{
    free((void*)buf);
    delete buffer;
}

bool server_read(server_state *state) 
{
    char *ptr = state->buf;
    int len = state->buf_len;
    int count = 0;

    while(state->buffer->read(ptr,1)>0)
    {
        if(*(ptr++) == '\0')
            break;
        count++;
        len--;
        if(!len) {
            state->buf_len += BUFSIZ;
            len += BUFSIZ;
            state->buf = (char*)realloc((void*)state->buf, state->buf_len);
            ptr = state->buf + count;
        }
    }

    state->last_result = state->buf[0];
    state->last_line = state->buf+1;
    if(debug) fprintf(stderr,"%s\n", state->buf);
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
    if(!server_send(state, line)) {
        if(debug) fprintf(stderr, "server_send aborted\n");
        return false;
    }
    if(!server_read(state)) {
        if(debug) fprintf(stderr, "server_read aborted\n");
        return false;
    }
    if(state->last_result == '-') {
        fprintf(stderr,"Error: %s\n", state->last_line);
        return false;
    }
    return true;
}

void handle_ls(struct server_state *state, const char *args)
{
    bool ret;

    if(!args || !*args) 
      ret = server_cmd(state, "LIST F");
    else
      ret = server_cmd(state, "LIST F %s", args);
    if(ret)
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_lls(struct server_state *state, const char *args)
{
    bool ret;

    if(!args || !*args) 
      ret = server_cmd(state, "LIST V");
    else
      ret = server_cmd(state, "LIST V %s", args);
    if(ret)
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_get(struct server_state *state, const char *args)
{
    if(!args || !*args) {
        fprintf(stderr, "Usage: get <file>\n");
        return;
    }
    const char *filename = basename(args);

    if(!server_cmd(state, "RETR %s", args))
        return;
    long length = strtoul(state->last_line, NULL, 10);
    void *buf = malloc(length);
    if(!buf) {
        fprintf(stderr, "Couldn't allocate memory: %s\n", filename, strerror(errno));
        server_cmd(state, "STOP");
        return;
    }
    FILE *f = fopen(filename, "w");
    if(!f) {
        fprintf(stderr, "Couldn't create %s: %s\n", filename, strerror(errno));
        server_cmd(state, "STOP");
        free(buf);
        return;
    }
    
    server_send(state, "SEND"); 
    length = recv(state->fd, buf, length, 0);
    if(length < 1) {
        fprintf(stderr, "Couldn't read file: %s\n", strerror(errno));
        free(buf);
        return;
    }
    fwrite(buf, length, 1, f);
    fclose(f);
    free(buf);
}

void handle_put(struct server_state *state, const char *args)
{
    if(!args || !*args) {
        fprintf(stderr, "Usage: put <file>\n");
        return;
    }
    const char *filename = basename(args);

    if(!server_cmd(state, "STOR OLD %s", args) || state->last_result != '+')
        return;

    FILE *f = fopen(filename,"r");
    if(!f) {
        fprintf(stderr, "Couldn't open %s: %s\n", filename, strerror(errno));
        server_cmd(state, "STOP");
        return;
    }

    fseek(f,0,SEEK_END);
    long length = ftell(f);
    fseek(f,0,SEEK_SET);

    void *buf = malloc(length);
    length = fread(buf, 1, length, f);

    if(!server_cmd(state, "SIZE %ld", length) || state->last_result != '+') {
        fclose(f);
        free(buf);
        return;
    }

    send(state->fd, buf, length, 0);
    fclose(f);
    free(buf);

    if(!server_read(state)) {
        if(debug) fprintf(stderr, "server_read aborted\n");
    }
    printf("%s\n", state->last_line);
}

void handle_rename(struct server_state *state, const char *args)
{
    if(!args || !*args) {
        fprintf(stderr, "Usage: rename <file1> <file2>\n");
        return;
    }

    const char *file1, *file2;
    file1 = file2 = args;
    while(!*file2 && !isspace(*file2))
        file2++; // TODO: Quote handling
  
    if(*file2) *(char*)(file2++) = '\0';
    while(*file2 && isspace(*file2)) file2++;
    if(!*file2) {
        fprintf(stderr, "Usage: rename <file1> <file2>\n");
        return;
    }

    if(!server_cmd(state, "NAME %s", file1))
        return;
    
    if(!server_cmd(state, "TOBE %s", file2))
        return;

    printf("%s\n", state->last_line);
}

void handle_remove(struct server_state *state, const char *args)
{
    if(!args || !*args) {
        fprintf(stderr, "Usage: rm <file>\n");
        return;
    }
    if(server_cmd(state, "KILL %s", args))
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_cd(struct server_state *state, const char *args)
{
    if(!args || !*args) {
        fprintf(stderr, "Usage: cd <directory>\n");
        return;
    }
    if(server_cmd(state, "CDIR %s", args))
        fprintf(stderr, "%s\n", state->last_line);
}

void handle_lcd(struct server_state *state, const char *args)
{
    if(!args || !*args) {
        fprintf(stderr, "Usage: lcd <directory>\n");
        return;
    }

    if(chdir(args))
        fprintf(stderr, "Error: %s\n", strerror(errno));
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
    printf("ls\t\tList files\n");
    printf("lls\t\tList files verbosely\n");
    printf("get <file>\tRetrieve file from server\n");
    printf("put <file>\tSend file to server");
    printf("mv <from> <to>\tRename file\n");
    printf("rm <file>\tDelete file\n");
    printf("cd\t\tChange remote directory\n");
    printf("lcd\t\tChange local directory\n");
    printf("type <a|b>\tAscii or Binary mode\n");
}

bool parse_line(struct server_state *state, const char *cmd, const char *args)
{
    if(!strcasecmp(cmd, "quit") || !strcasecmp(cmd, "exit"))
        return false;

    if(!*cmd)
        return true;

    if(!strcasecmp(cmd, "ls")) handle_ls(state, args);
    else if(!strcasecmp(cmd, "lls")) handle_lls(state, args);
    else if(!strcasecmp(cmd, "get")) handle_get(state, args);
    else if(!strcasecmp(cmd, "put")) handle_put(state, args);
    else if(!strcasecmp(cmd, "mv")) handle_rename(state, args);
    else if(!strcasecmp(cmd, "rm")) handle_remove(state, args);
    else if(!strcasecmp(cmd, "cd")) handle_cd(state, args);
    else if(!strcasecmp(cmd, "lcd")) handle_lcd(state, args);
    else if(!strcasecmp(cmd, "type")) handle_type(state, args);
    else if(!strcasecmp(cmd, "help")) handle_help();
    else if(!strcasecmp(cmd, "?")) handle_help();
    else printf("Invalid command %s\n", cmd);
    return true;
}

void read_commands(int server_fd)
{
    server_state state(server_fd);

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
        if(debug) fprintf(stderr,"USER failed, aborting\n");
        goto exit;
    }

    if(!server_cmd(state, "PASS %s", password) || state->last_result !='!') {
        if(debug) fprintf(stderr,"PASS failed, aborting\n");
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
    int fd;

    hints.ai_socktype = SOCK_STREAM;
    if((result=getaddrinfo(server, "115", &hints, &info)) != 0) {
        fprintf(stderr,"Unable to connect: %s\n",gai_strerror(result));
        return -1;
    }
    
    for(p=info; p; p=p->ai_next) {
        if((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) > 0) {
            if(connect(fd, p->ai_addr, p->ai_addrlen) == 0)
                break; 
            result = errno;
            close(fd);
        }
    }

    if(!p) {
        fprintf(stderr,"Unable to connect: %s\n",strerror(result));
        return -1;
    }

    server_state state(fd);

    if(!login(&state, username, password)) {
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