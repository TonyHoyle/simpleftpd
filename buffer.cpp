#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "buffer.h"

socketbuffer::socketbuffer(int socket)
{
    m_socket = socket;
    m_base = (unsigned char *)malloc(BUFSIZ);
    m_size = BUFSIZ;
    m_ptr = m_base;
    m_count = 0;
}

socketbuffer::~socketbuffer()
{
    free(m_base);
}

int socketbuffer::read(void *dst, int size)
{
    int total = 0;
    for(;;) {
        int left = m_count - (m_ptr-m_base);
        if(left >= size) {
            memcpy(dst, m_ptr, size);
            m_ptr += size;
            total += size;
            return total;
        }
        if(left > 0) {
            memcpy(dst, m_ptr, left);
            dst = ((unsigned char *)dst) + left;
            size -= left;
            total += left;
        }
        m_count = recv(m_socket, m_base, m_size, 0);
        if(m_count <= 0)
            return m_count;
        m_ptr = (unsigned char *)m_base;        
    }    
}
