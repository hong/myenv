#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <ctime>

using namespace std;

const int MAXS = 20*1024*1024;
char buf[MAXS];

void fread_analyse()
{
    freopen("baidu.html","rb",stdin);
    int len = fread(buf,1,MAXS,stdin);
    buf[len] = '\0';
}

#if 0
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
void mmap_analyse()
{
    int fd = open("data.txt",O_RDONLY);
    int len = lseek(fd,0,SEEK_END);
    char *mbuf = (char *) mmap(NULL,len,PROT_READ,MAP_PRIVATE,fd,0);    
}
#endif

int main()
{
    int start = clock();

    fread_analyse();    

    printf("%.3lf\n",double(clock()-start)/CLOCKS_PER_SEC);

    return 0;
}
