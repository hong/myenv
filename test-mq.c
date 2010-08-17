#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>		/* For O_* constants */
#include <sys/stat.h>		/* For mode constants */
#include <mqueue.h>

#define MSGMAX 10
#define MSGSIZEMAX 1024

int main(int argc, char **argv)
{
	struct mq_attr mqa;
	mqd_t mqdw;
	char buffer[MSGSIZEMAX];
	unsigned int priority = 0;
	int len = 0;

	mqa.mq_maxmsg = MSGMAX;
	mqa.mq_msgsize = MSGSIZEMAX;

	if ((mqdw =
	     mq_open("/valgrind-mqueue", O_CREAT | O_RDWR | O_NONBLOCK, 0600,
		     &mqa)) < 0) {
		if (errno == ENOSYS)
			exit(0);
		return -1;
	}

    char cmd[] = "PING";

	if (mq_send(mqdw, cmd, strlen(cmd), 0) < 0) {
		perror("mq_send");
        goto lzExit;
	}

	if ((len = mq_receive(mqdw, buffer, sizeof(buffer), &priority)) < 0) {
		perror("mq_receive");
        goto lzExit;
	}

    buffer[len] = '\0';

    printf("mesage len: %d, buf: %s\n", len, buffer);

	if (len != 4 || memcmp(buffer, "PING", 4) != 0) {
		fprintf(stderr, "Message corrupt!");
	}

	mq_getattr(mqdw, &mqa);
    printf("mesage curmsgs: %ld, flags: %ld\n", mqa.mq_curmsgs, mqa.mq_flags);

	if (mq_notify(mqdw, NULL) < 0) {
		perror("mq_notify");
        goto lzExit;
	}

#if 0
    struct mq_attr {
        long mq_flags;       /* Flags: 0 or O_NONBLOCK */
        long mq_maxmsg;      /* Max. # of messages on queue */
        long mq_msgsize;     /* Max. message size (bytes) */
        long mq_curmsgs;     /* # of messages currently in queue */
    };
#endif
	mq_getattr(mqdw, &mqa);
    printf("mesage curmsgs: %ld, flags: %ld\n", mqa.mq_curmsgs, mqa.mq_flags);

lzExit:
	mq_close(mqdw);
	mq_unlink("/valgrind-mqueue");
	return 0;
}
