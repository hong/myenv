#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *mystrncpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n && src[i] != '\0'; i++)
		dest[i] = src[i];
	for (; i <= n; i++)
		dest[i] = '\0';

	return dest;
}

int ReplaceStr(char *sSrc, char *sMatchStr, char *sReplaceStr)
{
	int strLen = 0;
	char *pNewString = NULL;

	char *FindPos = strstr(sSrc, sMatchStr);
	if ((!FindPos) || (!sMatchStr))
		return -1;

	//printf("%d, %d, %d \n", strlen(sMatchStr), strlen(sReplaceStr), strlen(sSrc));
	strLen = strlen(sMatchStr) + strlen(sReplaceStr) + strlen(sSrc);
	pNewString = calloc(1, strLen);
	if (pNewString == NULL)
		return -1;

	while (FindPos) {
		memset(pNewString, 0x0, sizeof(pNewString));
		strLen = FindPos - sSrc;
		mystrncpy(pNewString, sSrc, strLen);
		//printf("pNewString=%s\n", pNewString);
		strcat(pNewString, sReplaceStr);
		strcat(pNewString, FindPos + strlen(sMatchStr));
		strcpy(sSrc, pNewString);

		FindPos = strstr(sSrc, sMatchStr);
	}

	return 0;
}

int main()
{
	char str[128] = "(IPPING-RESULT)";

	printf("str=%s\n", str);

	ReplaceStr(str, "(", "\\50");
	ReplaceStr(str, ")", "\\051");

	printf("str=%s\n", str);

	return 0;
}
