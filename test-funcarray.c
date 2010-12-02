#include <stdio.h> 
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

typedef struct Connection_Info {
	int index;
	const char* text;
} Connection_Info;

typedef struct Transfer_Info {
    int transferID;
    int groupID;
    int cntError;
} Transfer_Info;

typedef void (* report_serverstatistics)( Connection_Info*, Transfer_Info* );

void reporter_serverstats( Connection_Info *nused, Transfer_Info *stats )
{
	printf("nused->index=%d, nused->text=%s\n", nused->index, nused->text);
	printf("stats->transferID=%d, stats->groupID=%d\n", stats->transferID, stats->groupID);
}

void CSV_serverstats( Connection_Info *conn, Transfer_Info *stats )
{
	printf("conn->index=%d \tconn->text=%s\n", conn->index, conn->text);
	printf("stats->transferID=%d \tstats->groupID=%d\n", stats->transferID, stats->groupID);
}

report_serverstatistics serverstatistics_reports[2] = {
	reporter_serverstats,
	CSV_serverstats
};

int main(int argc, char** argv)  
{
	Connection_Info connection;
	Transfer_Info info;

	memset(&connection, 0, sizeof(Connection_Info));
	memset(&info, 0, sizeof(Transfer_Info));

	connection.index = 1;
	connection.text = "hello c";

	info.transferID = 1;
	info.transferID = 1;

	serverstatistics_reports[0]( &connection, &info );
	serverstatistics_reports[1]( &connection, &info );

    return 0;
}
