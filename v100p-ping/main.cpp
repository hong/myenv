#include "cnettest_ping.h"

static CNetTest_Ping* pPingTest = NULL;
static void ping_kill_sighandler(int sigNum);

int main(int argc, char* argv[])
{
	signal(SIGINT, ping_kill_sighandler);
	signal(SIGHUP, ping_kill_sighandler);
	signal(SIGTERM, ping_kill_sighandler);

	pPingTest = new CNetTest_Ping();
	if (pPingTest != NULL)
	{
		if (pPingTest->applyTestSetting(argc, argv) == 0)
		{
			pPingTest->startTest();
			pPingTest->onMainLoop();
		}
	}

	if (pPingTest != NULL)
		delete pPingTest;
	pPingTest = NULL;

	return 0;
}

static void ping_kill_sighandler(int sigNum)
{
	if (pPingTest != NULL)
	{
		pPingTest->exitExec();
	}
}

