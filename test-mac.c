#include <stdio.h>
#include <string.h>

int main(void)
{
	int cnt = 0;
	unsigned int buf[6];
	unsigned char mac[6];

	cnt = sscanf("00-18-63-00-0C-40", "%2X-%2X-%2X-%2X-%2X-%2X", buf, buf+1, buf+2, buf+3, buf+4, buf+5);
	printf("cnt=%d\n", cnt);

	mac[0] = (unsigned char)buf[0];
    mac[1] = (unsigned char)buf[1];
    mac[2] = (unsigned char)buf[2];
    mac[3] = (unsigned char)buf[3];
    mac[4] = (unsigned char)buf[4];
    mac[5] = (unsigned char)buf[5];

	fprintf(stderr, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return 0;
}
