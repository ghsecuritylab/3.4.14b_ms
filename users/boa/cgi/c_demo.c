#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../apmib/apmib.h"
#include "../src/deviceProcIf.h"

static struct ifstatRate wanRate;
#define WEB_TOPOLOGY_SIZE 10240

char* get_cgi_data(FILE* fp, char* method)
{
    char* input;
    int len;
    int size=1024;
    int i=0;

    if (strcmp(method, "GET") == 0)  /**< GET method */
    {
        input = getenv("QUERY_STRING");
        return input;
    }
    else if (strcmp(method, "POST") == 0)  /**< POST method */
    {
        len = atoi(getenv("CONTENT_LENGTH"));
        input = (char*)malloc(sizeof(char) * (size+1));

        if (len == 0)
        {
            input[0] = '\0';
            return input;
        }

        while (1)
        {
            input[i] = (char)fgetc(fp);
            if (i == size)
            {
                input[i+1] = '\0';
                return input;
            }
            --len;

            if (feof(fp) || (!(len)))
            {
                i++;
                input[i] = '\0';
                return input;
            }
            i++;
        }
    }
    return NULL;
}

extern int  webMeshTopology (char *topology);
int main(void)
{
	char *data;
	char* input;
	time_t current;
	char buffer[512];
	int upspeed = 222;
	int downspeed = 1067;
	char rxRate[32] = {0};
	char txRate[32] = {0};
	char* method;
	char topology[WEB_TOPOLOGY_SIZE];
	
	printf("content-type:text/html\r\n\r\n");  

	wanRate.ifname="eth1";
	getProcIfData(&wanRate);

	if (((int)wanRate.txRate*8) < 1000)
		sprintf(txRate, "%.2lfKbps", wanRate.txRate*8);
	else
		sprintf(txRate, "%.2lfMbps", wanRate.txRate*8/1000);

	if (((int)wanRate.rxRate*8) < 1000)
		sprintf(rxRate, "%.2lfKbps", wanRate.rxRate*8);
	else
		sprintf(rxRate, "%.2lfMbps", wanRate.rxRate*8/1000);

	method = getenv("REQUEST_METHOD");
	input = get_cgi_data(stdin, method);

	memset(topology, 0, sizeof(topology));
	webMeshTopology(topology);

	if(input==NULL)    
	{
		printf("ret:upspeed=%sTX&downspeed=%sRX");  
	}
	else
	{
		printf("ret:upspeed=%sTX&downspeed=%sRX&%s", txRate, rxRate, topology);
	}
	
	return 0;
}


