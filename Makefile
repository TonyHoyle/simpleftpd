CPPFLAGS=-g
LDFLAGS=-lpam -lreadline

all: sftp sftpd

sftp: sftp.cpp buffer.cpp buffer.h

sftpd: sftpd.cpp

clean: 
	rm sftp sftpd

