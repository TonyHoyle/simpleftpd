//
// Implementation of SFTP (RFC913) https://tools.ietf.org/html/rfc913
//
// Not to be confused with Secure FTP which is a much later and more complex protocol
//
// By Tony Hoyle <tony@hoyle.me.uk>
// Licensed under the GNU GPL
//
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>
#include <errno.h>
#include <security/pam_appl.h> 
#include <security/pam_misc.h> 
#include <pwd.h>
#include <ctype.h>
#include <dirent.h>
#include <getopt.h>

static struct __flags {
    bool debug;
    bool foreground;
    bool inetd;
} flags;

typedef struct __state {
    int fd;
    const char *user;
    bool loggedin;
    bool binary;
    FILE *current_file;
} state_t;

static void vlog(int priority, const char *format, va_list vargs)
{
    char tmp[256];
    vsnprintf(tmp, sizeof(tmp), format, vargs);
    syslog(priority, "%s", tmp);
    if(flags.foreground)
        fprintf(stderr, "%s\n", tmp);
}

static void log(int priority, const char *format, ...)
{
    char buf[256];

    va_list vargs;
    va_start (vargs, format);
    vlog(priority, format, vargs);
    va_end(vargs);
}

static void die (const char * format, ...)
{
    char buf[256];

    va_list vargs;
    va_start (vargs, format);
    vlog(LOG_ERR, format, vargs);
    va_end (vargs);
    exit (1);
}

static int reply(int fd, const char *format, ...)
{
    char buf[256];

    va_list vargs;
    va_start (vargs, format);
    int len = vsnprintf (buf, sizeof(buf), format, vargs);
    va_end (vargs);
    return write(fd, buf, len);
}

// Partial replies end in CRLF not NULL
static int reply_partial(int fd, const char *format, ...)
{
    char buf[256];

    va_list vargs;
    va_start (vargs, format);
    int len = vsnprintf (buf, sizeof(buf), format, vargs);
    va_end (vargs);
    buf[len-1] = '\r';
    buf[len] = '\n';
    return write(fd, buf, len+1);
}

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

int opensocket()
{
    const char* hostname=0; /* wildcard */
    const char* portname="115";

    struct addrinfo hints;
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;
    struct addrinfo* res=0;
    int err=getaddrinfo(hostname,portname,&hints,&res);
    if (err!=0) {
        die("failed to resolve local socket address: %s",gai_strerror(err));
    }

    int server_fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if (server_fd==-1) {
        die("Unable to open socket: %s",strerror(errno));
    }

    int reuseaddr=1;
    if (setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&reuseaddr,sizeof(reuseaddr))==-1) {
        die("Unable to set socket options: %s",strerror(errno));
    }

    if (bind(server_fd,res->ai_addr,res->ai_addrlen)==-1) {
        die("Unable to bind: %s",strerror(errno));
    }

    freeaddrinfo(res);

    if (listen(server_fd,SOMAXCONN)) {
        die("failed to listen for connections: %s",strerror(errno));
    }
    
    return server_fd;
}

void handle_session(int fd, const char *remote_host);

void dispatch(int server_fd)
{
    struct sockaddr_storage sa;
    socklen_t sa_len=sizeof(sa);
    int session_fd;

    if(server_fd != 0) {
        session_fd=accept(server_fd,(struct sockaddr*)&sa,&sa_len);    
        if (session_fd==-1) {
            if (errno==EINTR) return;
            die("failed to accept connection: %s",strerror(errno));
        }
    } else {
        session_fd = 0;
        if(getpeername(server_fd, (struct sockaddr*)&sa, &sa_len)<0) {
            die("failed to get socket peer: %s",strerror(errno));
        }
    }

    char remotename[INET6_ADDRSTRLEN];
    int err=getnameinfo((struct sockaddr*)&sa,sa_len,remotename,sizeof(remotename),0,0,NI_NUMERICHOST);
    if (err!=0) {
        snprintf(remotename,sizeof(remotename),"invalid address");
    }

    pid_t pid=fork();
    if (pid==-1) {
        die("failed to create child process (errno=%d)",errno);
    } else if (pid==0) {
        if(server_fd != 0) close(server_fd);
        handle_session(session_fd, remotename);
        if(session_fd != 0) close(session_fd);
        _exit(0);
    } else {
        if(session_fd != 0) close(session_fd);
    }
}

void user(state_t *state, const char *args);
void acct(state_t *state, const char *args);
void pass(state_t *state, const char *args);
void type(state_t *state, const char *args);
void list(state_t *state, const char *args);
void cdir(state_t *state, const char *args);
void kill(state_t *state, const char *args);
void name(state_t *state, const char *args);
void retr(state_t *state, const char *args);
void stor(state_t *state, const char *args);

struct __cmd { const char *cmd; void(*handler)(state_t *, const char *); };
static struct __cmd cmds[] = 
{
    { "USER", user},
    { "ACCT", acct},
    { "PASS", pass},
    { "TYPE", type},
    { "LIST", list},
    { "CDIR", cdir},
    { "KILL", kill},
    { "NAME", name},
    { "RETR", retr},
    { "STOR", stor},
    { 0, 0}
};


void handle_session(int fd, const char *remote_host)
{
    log(LOG_INFO, "Connection from %s", remote_host);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    reply(fd, "+%s SFTP Service", hostname);

    state_t state = {0};
    char cmd[128];

    state.fd = fd;
    for(;;) {
        if(readcmd(fd, cmd, sizeof(cmd)) < 0)
            return;
        log(LOG_DEBUG, "Command received: %s", cmd);
        char *args = strchr(cmd, ' ');
        if(args != NULL) 
            *(args++)='\0';
        
        if(!strcasecmp(cmd, "DONE")) {
            reply(fd, "+%s closing connection", hostname);
            return;
        }

        struct __cmd *handler = cmds;
        while(handler->cmd) {
            if(!strcasecmp(cmd, handler->cmd)) {
                handler->handler(&state, args);
                break;
            }
            handler++;
        }
        if(!handler->cmd) 
            reply(fd, "-%s Bad Command", cmd);
    }
}

///////////////////////////////////////////////////////

void user(state_t *state, const char *args)
{
    if(state->loggedin) {
        reply(state->fd, "-Already logged in");
        return;
    }
    state->user = strdup(args);
    reply(state->fd, "+%s ok, send password", state->user);
}

void acct(state_t *state, const char *args)
{
    reply(state->fd, "-Not implemented");
}

static int my_conv(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr)
{
    const struct pam_message* msg_ptr = *msg;
    struct pam_response * resp_ptr = NULL;
    int x = 0;
    *resp = (pam_response *)calloc(sizeof(struct pam_response), num_msg);
    for (x = 0; x < num_msg; x++, msg_ptr++) {
        switch (msg_ptr->msg_style){
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON:
                resp[x]->resp = strdup((char*)appdata_ptr);
                break;

            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                break;

            default:
                return PAM_ABORT;
        }
    }
    return PAM_SUCCESS;    
}

void pass(state_t *state, const char *args)
{
    if(state->loggedin) {
        reply(state->fd, "-Already logged in");
        return;
    }
    if(!state->user) {
        reply(state->fd, "-Username not sent");
        return;
    }

    pam_handle_t *pamh;
    struct pam_conv pamc = { my_conv, (void*)args };
    struct passwd *pw;
    const char *user;

    pam_start("sftp", state->user, &pamc, &pamh);
    int result = pam_authenticate(pamh,
            PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);
    if(result == PAM_SUCCESS)
        result = pam_get_item(pamh, PAM_USER, (const void **)&user);
    if (result == PAM_SUCCESS)
        result = pam_acct_mgmt(pamh, 0);    

    if (result == PAM_SUCCESS) {
        if((pw = getpwnam(user)) == NULL) {
            log(LOG_ERR, "User does not exist on the system");
            result = PAM_AUTH_ERR;
        }
    }

    if(result == PAM_SUCCESS) {
        if(!pw->pw_uid) {
            log(LOG_ERR, "Login to uid 0 not allowed");
            result = PAM_AUTH_ERR;
        } 
        else if(setegid(pw->pw_gid) ||
                seteuid(pw->pw_uid)) {
            log(LOG_ERR, "Unable to drop privileges");
            result = PAM_AUTH_ERR;
        } else if(chdir(pw->pw_dir)) {
            log(LOG_ERR, "Couldn't change to home directory");
            result = PAM_AUTH_ERR;
        }
    }
       
    if(result == PAM_SUCCESS) {
        state->loggedin = true;
        reply(state->fd,"!Logged in");
    }
    else {
        setegid(getgid());
        seteuid(getuid());

        log(LOG_ERR, "Login failure");

        state->loggedin = false;
        reply(state->fd,"-Wrong password, try again");
    }
    pam_end(pamh, result);
}

void type(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    switch(tolower(args[0])) {
        case 'a':
            state->binary = false;
            reply(state->fd,"+Using Ascii mode");
            break;
        case 'b':
            state->binary = true;
            reply(state->fd,"+Using Binary mode");
            break;
        case 'c':
            state->binary = true;
            reply(state->fd,"+Using Continuous mode");
            break;
        default:
            reply(state->fd,"-Type not valid");
            break;
    }
}

static void list_files(state_t *state, const char *dir)
{
    DIR *entry = opendir(dir);
    if(!dir) {
        reply(state->fd, "-%s", strerror(errno));
        return;
    }

    char curdir[256];
    reply_partial(state->fd, "+%s", getcwd(curdir, sizeof(curdir)));

    struct dirent *ent;
    while(ent = readdir(entry)) {
        reply_partial(state->fd, ent->d_name);
    }

    reply(state->fd,"");

    closedir(entry);
}

static void list_verbose(state_t *state, const char *dir)
{
    DIR *entry = opendir(dir);
    if(!dir) {
        reply(state->fd, "-%s", strerror(errno));
        return;
    }

    char curdir[256];
    reply_partial(state->fd, "+%s", getcwd(curdir, sizeof(curdir)));

    struct dirent *ent;
    while(ent = readdir(entry)) {
        //TODO: Build ls -l results
        reply_partial(state->fd, ent->d_name);
    }

    reply(state->fd,"");

    closedir(entry);
}

void list(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    char kind = tolower(args[0]);

    if(args[1] && args[1]!=' ') {
        reply(state->fd,"-Bad list kind");
        return;
    }

    if(args[1]) args+=2;
    else   
        args=NULL;

    switch(kind) {
        case 'f': list_files(state, args); break;
        case 'v': list_verbose(state, args); break;
        default:
            reply(state->fd, "-Bad list kind");
    }
}

void cdir(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    if(chdir(args)) {
        char cwd[128];
        reply(state->fd, "!Changed working-dir to %s",getcwd(cwd, sizeof(cwd)));
    } else {
        reply(state->fd, "-Can't connect to directory because %s", strerror(errno));
    }
}

void kill(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    reply(state->fd, "-Not implemented");
}

void name(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }
    
    reply(state->fd, "-Not implemented");
}

void retr(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    if(state->current_file) {
        fclose(state->current_file);
    }

    log(LOG_DEBUG, "Read file ",args);

    state->current_file = fopen(args, state->binary?"b":"t");
    if(state->current_file == NULL) {
        log(LOG_INFO, "Read failed: %s", strerror(errno));
        reply(state->fd, "-%s", strerror(errno));
        return;
    }

    fseek(state->current_file, 0, SEEK_END);
    long len = ftell(state->current_file);
    fseek(state->current_file, 0, SEEK_SET);
    reply(state->fd, " %ld", len);
}

void send(state_t *state, const char *args)
{
   if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    if(!state->current_file) {
        reply(state->fd,"-Bad command");
        return;
    }

    char mem[BUFSIZ];
    int len;

    while(len=fread(mem, 1024, 1, state->current_file)>0) {
        write(state->fd, mem, len);
    }
    fclose(state->current_file);
    state->current_file = NULL;
}

void stop(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    if(!state->current_file) {
        reply(state->fd,"-Bad command");
        return;
    }

    fclose(state->current_file);
    state->current_file = NULL;
    reply(state->fd, "+ok, RETR aborted");
}

void stor(state_t *state, const char *args)
{
    if(!state->loggedin) {
        reply(state->fd,"-Not logged in");
        return;
    }

    reply(state->fd, "-Not implemented");
}

void usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s [--debug][--foreground][--inetd][-d][-f][-i]\n", cmd);
}

int main(int argc, char **argv)
{
    static struct option long_options[] =
    {
        /* These options set a flag. */
        {"debug",      no_argument,   0, 'd'},
        {"foreground", no_argument,   0, 'f'},
        {"inetd",      no_argument,   0, 'i'},
        {"help",       no_argument,   0, 'h'},
        {0}
    };

    while(true) {
        /* getopt_long stores the option index here. */
        int option_index = 0;

        int c = getopt_long (argc, argv, "dfih",
                        long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;
        switch(c) {
            case 'd': flags.debug = true; break;
            case 'f': flags.foreground = true; break;
            case 'i': flags.inetd = true; break;
            case 'h': usage(argv[0]); return 0;
            case '?': break;
            default: abort();
        }
    }

    if(optind < argc) {
        usage(argv[0]);
        return 0;
    }

    if(!flags.foreground) {
        int err = daemon(0,0);
        if(err < 0)
            return err;
    }

    openlog("slog", LOG_PID|LOG_CONS, LOG_DAEMON);
    int fd;
    if(flags.inetd)
        fd = 0;
    else
        fd = opensocket();
    for(;;) {
        dispatch(fd);
    }
    closelog();
}