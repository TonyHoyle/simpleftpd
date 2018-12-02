#ifndef BUFFER__H
#define BUFFER__H

class socketbuffer
{
    private:
        unsigned char *m_base;
        unsigned char *m_ptr;
        int m_size;
        int m_socket;
        int m_count;

    public:
        socketbuffer(int socket);
        ~socketbuffer();

        int read(void *dst, int size);
};

#endif
