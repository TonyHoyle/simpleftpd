CFLAGS=-g
LDFLAGS=-lpam -lreadline

all: sftp sftpd

sftp: sftp.cpp

sftpd: sftpd.cpp

clean: 
	rm sftp sftpd

