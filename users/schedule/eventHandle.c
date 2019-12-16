
/*
Copyright (c) 2019, All rights reserved.

File         : timer.c
Status       : Current
Description  : 

Author       : haopeng
Contact      : 376915244@qq.com

Revision     : 2019-08 
Description  : Primary released

## Please log your description here for your modication ##

Revision     : 
Modifier     : 
Description  : 

*/

#include <stdio.h>     
#include <time.h>       /* time_t, struct tm, time, localtime */
#include "apmib.h"
#include "../appserver/appFun.h"


#define	TIMER_CONTINUE	0
#define	TIMER_REMOVE	1
#define WEEK_NUM        7
#define WEEK_TIME_DISABLED 7
#define  SUNDAY 	 0
#define  MONDAY 	 1
#define  TUESDAY	 2
#define  WEDNESDAY	 3
#define  THURSDAY	 4
#define  FRIDAY 	 5
#define  SATDAY 	 6
#define  PARENT_CONTRL_SET_COMMAND    "sysconf firewall addParentControl %d"
#define  PARENT_CONTRL_DELETE_COMMAND "sysconf firewall deleteParentControl %d"





char* convertTimeToString(const struct tm* timeptr)
{  
static const char weekName[][4] = {    
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"  
	};  
static char result[40]={0};  
sprintf(result, "%d-%.2d-%.2d %.2d:%.2d:%.2d",    
	1900+timeptr->tm_year,    
	timeptr->tm_mon+1,    
	timeptr->tm_mday,    
	timeptr->tm_hour,    
	timeptr->tm_min,
	timeptr->tm_sec);  
return result;
}

/*
struct tm:
tm_sec :econds after the minute range 0-59
tm_min :minutes after the hour  range 0-59
tm_hour:hours since midnight    range 0-23
tm_mday:day of the month        range 1-31
tm_mon: months since January    range 0-11
tm_year:years since 1900
tm_wday: days since Sunday      range 0-6 ,0=sunday 1=Mon 2=Tues....
tm_yday days since January 1    range 0-365
*/
#if 0
int getCurrentTime(struct tm timeinfo)
{
    time_t rawtime;  
	struct tm* timeinfo;
	time (&rawtime);  
	timeinfo = localtime(&rawtime);  
	printf("current local time: %s\n", convertTimeToString(timeinfo)); 
	//strcpy(date,convertTimeToString(timeinfo));
	//return date;
	return 0;
}
#endif


#if 1

enum DEV_TYPE{
	TYPE_HOSTNAME = 0,
	TYPE_MAC
};

int get_dev_type(char *p_dst)
{
	if (strlen(p_dst) != strlen("00:00:00:00:00:00"))
		return TYPE_HOSTNAME;

	return TYPE_MAC;
}

int get_mac_from_hostname(char *mac, char* hostname)
{
	RTK_LAN_DEVICE_INFO_T devinfo[MAX_STA_NUM] = {0};
	int nBytesSent=0;
	int num = 0;
	int i=0;
	char macEntry[32]={0};
	rtk_get_lan_device_info(&num, devinfo, MAX_STA_NUM);

	for (i=0; i < num; i++)
	{
		if (!strcmp(hostname, devinfo[i].hostname))
		{
			sprintf(macEntry, "%02x:%02x:%02x:%02x:%02x:%02x", 
				devinfo[i].mac[0], devinfo[i].mac[1], devinfo[i].mac[2], devinfo[i].mac[3],devinfo[i].mac[4],devinfo[i].mac[5]);
			strcpy(mac, macEntry);
			return 1;
		}
	}
	
	return 0;
}

typedef struct parental_control_dev_info
{
	int  dev_num;
	char mac[MAX_STA_NUM][32];
	char hostname[MAX_STA_NUM][64];
}PARENTAL_CONCTROL_DEV_INFO, *PARENTAL_CONCTROL_DEV_INFO_P;

int transform_parental_dev(char *p_list, PARENTAL_CONCTROL_DEV_INFO_P parental_dev)
{
	int ret = 0;
	char *p_tmp = 0;
	char buffer[128] = {0};
	char sta_mac[32] = {0};
	int i;
	
	if (strlen(p_list)<=0)
		return -1;

	p_tmp = strstr(p_list, ";");
	if (p_tmp==NULL)
	{
		ret = get_dev_type(p_list); 	
		if (ret == TYPE_MAC)
		{
			strcpy(parental_dev->mac[parental_dev->dev_num], p_list);
			parental_dev->dev_num++;
		}
		else
		{
			strcpy(parental_dev->hostname[parental_dev->dev_num], p_list);
			memset(sta_mac, 0, sizeof(sta_mac));
			if(get_mac_from_hostname(sta_mac, p_list))
				strcpy(parental_dev->mac[parental_dev->dev_num], sta_mac);
			parental_dev->dev_num++;
		}
	}
	else
	{
		while (p_tmp!=NULL)
		{
			memset(buffer, 0, sizeof(buffer));
			strncpy(buffer, p_list, p_tmp-p_list);
			ret = get_dev_type(buffer); 	
			if (ret == TYPE_MAC)
			{
				strcpy(parental_dev->mac[parental_dev->dev_num], buffer);
				parental_dev->dev_num++;
			}
			else
			{
				strcpy(parental_dev->hostname[parental_dev->dev_num], buffer);
				memset(sta_mac, 0, sizeof(sta_mac));
				if(get_mac_from_hostname(sta_mac, buffer))
					strcpy(parental_dev->mac[parental_dev->dev_num], sta_mac);
				parental_dev->dev_num++;
			}
			p_list=p_tmp+1;
			p_tmp = strstr(p_list, ";");
		}
	}
	
	return 0;
}
void toUpper(char *str)
{
	int i=0;
	while(str[i]!=0)
	{
		if((str[i]>='a')&&(str[i]<='z'))
		str[i]-=32;
		i++;
	}
}

/*
	return 1 :find it ; 
*/
int isInIptables(char *mac)
{
	int i = 0;
	char buf[1024] = {0};
	FILE *fp = NULL;
	if (strlen(mac) == 0)
		return -1;

	fp = popen("iptables -nvL | grep \"DROP\"", "r");
	if(fp == NULL)
	{
		perror("popen error\n");
		return -1;
	}
	
	while(fgets(buf, sizeof(buf), fp) != 0)
	{
		toUpper(mac);
		if (NULL != strstr(buf, mac))
		{
			pclose(fp);
			return 1;
		}	
		memset(buf, 0x0, sizeof(buf));
	}
	
	pclose(fp);
	return 0;
}

/*
	return: 
	0:the rules not need to set;
	1:the rules need to set;		
*/
int isNeedSetIptables(char *p_terminal)
{
	char hostname[64] = {0};
	int i=0;
	int j = 0;
	char cmd[64] = {0};

	PARENTAL_CONCTROL_DEV_INFO	dev_info;
	
	if (strlen(p_terminal) == 0)
		return -1;

	memset(&dev_info, 0, sizeof(dev_info));
	
	transform_parental_dev(p_terminal, &dev_info);

	for (i=0; i<dev_info.dev_num; i++)
	{
		if (1 != isInIptables(dev_info.mac[i]))
			return 1;
	}
	return -1;
}
#endif

int parentContrlList()
{
	int nBytesSent=0, parentEntryNum, i,j;
	PARENT_CONTRL_T entry;
	int curentTime;
	char commandBuf[64]={0};

	time_t rawtime;  
	struct tm* currentTimeInfo;
	time (&rawtime);  
	currentTimeInfo = localtime(&rawtime); 
	//printf("current local time: %s\n", convertTimeToString(currentTimeInfo)); 

	if ( !apmib_get(MIB_PARENT_CONTRL_TBL_NUM, (void *)&parentEntryNum)) {
  		fprintf(stderr, "Get table entry error!\n");
		return -1;
	}
    
	for (i=1; i<=parentEntryNum; i++) 
	{

		*((char *)&entry) = (char)i;

		//	memset(&entry, 0x00, sizeof(entry));
		if ( !apmib_get(MIB_PARENT_CONTRL_TBL, (void *)&entry))
			return -1;
		//printf("------>function_%s_line[%d]: terminalNUm=%d\n",__FUNCTION__,__LINE__,parentEntryNum);

		//printf("\n(---+++++table--%d)tmpMon=%d tmpTues=%d  tmpWed=%d  tmpThur=%d  tmpFri=%d tmpSat=%d  tmpSun=%d  tmpstart=%d  tmpend=%d terminal=%s\n", \
		i,entry.parentContrlWeekMon,entry.parentContrlWeekTues,entry.parentContrlWeekWed,\
		entry.parentContrlWeekThur,entry.parentContrlWeekFri,entry.parentContrlWeekSat, \
		entry.parentContrlWeekSun, entry.parentContrlStartTime,entry.parentContrlEndTime,entry.parentContrlTerminal);
		//getCurrentTime(currentTimeInfo);
		curentTime=(currentTimeInfo->tm_hour*60+currentTimeInfo->tm_min);
		if((currentTimeInfo->tm_wday==(entry.parentContrlWeekMon?MONDAY:WEEK_TIME_DISABLED)) \
		||(currentTimeInfo->tm_wday==(entry.parentContrlWeekTues?TUESDAY:WEEK_TIME_DISABLED)) \
		||(currentTimeInfo->tm_wday==(entry.parentContrlWeekWed?WEDNESDAY:WEEK_TIME_DISABLED)) \
		||(currentTimeInfo->tm_wday==(entry.parentContrlWeekThur?THURSDAY:WEEK_TIME_DISABLED)) \
		||(currentTimeInfo->tm_wday==(entry.parentContrlWeekFri?FRIDAY:WEEK_TIME_DISABLED)) \
		||(currentTimeInfo->tm_wday==(entry.parentContrlWeekSat?SATDAY:WEEK_TIME_DISABLED)) \
		||(currentTimeInfo->tm_wday==(entry.parentContrlWeekSun?SUNDAY:WEEK_TIME_DISABLED))) \
		{
		 	//printf("------>function_%s_line[%d]: parent week is ok \n",__FUNCTION__,__LINE__);
		 if((curentTime>=entry.parentContrlStartTime)&&(curentTime<=entry.parentContrlEndTime) )
		 {
			if (isNeedSetIptables(entry.parentContrlTerminal) == 1)
			{
				memset(commandBuf,0,sizeof(commandBuf));
				sprintf(commandBuf,PARENT_CONTRL_SET_COMMAND,i);
				system(commandBuf);
			}

		 }
		 else if((curentTime>entry.parentContrlEndTime)&&(curentTime<=(entry.parentContrlEndTime+1)))
		 {	 
		    memset(commandBuf,0,sizeof(commandBuf));
		 	sprintf(commandBuf,PARENT_CONTRL_DELETE_COMMAND,i);
		 	system(commandBuf);
		 }
		}
	}
	return TIMER_CONTINUE;
}


int parentContrl(void *data, int reason )
{
    int intVal=0;
    apmib_get(MIB_PARENT_CONTRL_ENABLED,  (void *)&intVal);
	if(intVal==1){
     parentContrlList();
	}
	 
	 return TIMER_CONTINUE;  
}


