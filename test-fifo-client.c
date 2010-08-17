#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define  FIFO      "/tmp/myfifo"
#define  MAXLINE   128

int main(void)
{
	int fifo;
	char buf[MAXLINE];
	int len;
	int i = 0;

	strcpy(buf, "10");
	if ((fifo = open(FIFO, O_RDWR)) < 0)	//读写打开有名管道  
	{
		printf("mkfifo   error:   %s\n", strerror(errno));
		return (0);
	}
	while (i < 10) {
		sprintf(buf, "%d", i + 1);
		len = write(fifo, buf, strlen(buf));	//写入信息到管道中  
		printf("send   len   =   %d\n", len);
		sleep(i);
		i++;
	}

    close(fifo);

	return (0);
}
