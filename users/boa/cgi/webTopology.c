#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#define WEB_TOPOLOGY_TXT "/tmp/web_topology.txt"

#define WEB_TOPOLOGY_SIZE 10240

int  webMeshTopology (char *topology)
{
	int  fd = 0;
	int  len = 0;
	char buf[WEB_TOPOLOGY_SIZE];

	fd = open(WEB_TOPOLOGY_TXT, O_RDONLY);
	if (fd < 1)
	{
		strcpy(topology, "{}");
		return -1;
	}
	len = read(fd, buf, WEB_TOPOLOGY_SIZE);

	close(fd);

	if (len > 1)
	{
		strncpy(topology, buf, WEB_TOPOLOGY_SIZE);
	}
	else
	{
		strcpy(topology, "{}"); 
		return -1;
	}

	return 0;
} /* ----- End of main() ----- */
