#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	//char ipaddr[] = "http://192.168.0.101/test/222222222";
	char ipaddr[] = "192.168.0.101/test/222222222";
	char url[64] = "";
	char *p = NULL;
	int i = 0;

    if (strncmp(ipaddr, "http://", 7) == 0)
		p = ipaddr + 7;
	else
		p = ipaddr;

	while (*p != '\0')
	{
		//printf("%c\n", *p);
		if (*p == '/')
			break;
		url[i++] = *p++;
	}
	url[i] = '\0';

	printf("url=%s\n", url);

	return 0;
}
