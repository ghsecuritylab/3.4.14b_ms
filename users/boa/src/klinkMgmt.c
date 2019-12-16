/*
Copyright (c) 2019, All rights reserved.

File         : klinkMgmt.c
Status       : Current
Description  : 

Author       : haopeng
Contact      : 376915244@qq.com

Revision     : 2019-10 
Description  : Primary released

## Please log your description here for your modication ##

Revision     : 
Modifier     : 
Description  : 

*/

#include<stdio.h> 
#include<stdlib.h> 
#include<string.h>
#include <unistd.h>   
#include <arpa/inet.h>    
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<sys/ioctl.h>
#include <net/route.h>
#include <net/if.h>

#include "apmib.h"
#include "cJSON.h"
#include "./../../klink/klink.h"
extern convertIntToString(char* str, int intnum);
extern KlinkNode_t* initKlinkListHead();
extern KlinkNode_t *addKlinkListNode(KlinkNode_t*head,char* date,int type);
extern KlinkNode_t* serchKlinkListNode(KlinkNode_t*head,char*  date);
extern KlinkNode_t* deletKlinkListNode(KlinkNode_t*head,char* date);
extern void showKlinkNode(KlinkNode_t*head);
//static KlinkNode_t  klinkNodeData;
extern  unsigned char *fwVersion;
 KlinkNode_t* g_pKlinkHeadNode;



#define  DEVICE_INFO_VERSION 0
#define  DEVICE_INFO_SN 1	
#define  FOUND_TARGET_SUCC   1
#define  FOUND_TARGET_FAIL   0

#define  SLAVE_NUM   15
static int g_slaveNum=0;



static *etherAddrToString(etherAddr_t *ether, int type)
{
    static char buffer[8][64];
    static int buffer_index = 0;

    if (buffer_index >= sizeof(buffer)/sizeof(buffer[0]) - 1)
    {
        buffer_index = 0;
    }
    else 
    {
        buffer_index ++;
    }

    if (type == ETHER_TYPE_DEFAULT)
    {
        type = ETHER_ADDR_TYPE_DEFAULT;
    }
    
    switch(type)
    {
        case ETHER_TYPE_NO_SEPARTOR:
            sprintf(buffer[buffer_index], "%02x%02x%02x%02x%02x%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);
            break;
        case ETHER_TYPE_ONE_COLON:
            sprintf(buffer[buffer_index], "%02x%02x%02x:%02x%02x%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);  
            break;
        case ETHER_TYPE_ONE_DASH:
            sprintf(buffer[buffer_index], "%02x%02x%02x-%02x%02x%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);  
            break;            
        case ETHER_TYPE_TWO_COLON:
            sprintf(buffer[buffer_index], "%02x%02x:%02x%02x:%02x%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);  
            break;            
        case ETHER_TYPE_TWO_DASH:
            sprintf(buffer[buffer_index], "%02x%02x-%02x%02x-%02x%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);  
            break;            
        case ETHER_TYPE_FIVE_COLON:
            sprintf(buffer[buffer_index], "%02x:%02x:%02x:%02x:%02x:%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);  
            break;            
        case ETHER_TYPE_FIVE_DASH:
            sprintf(buffer[buffer_index], "%02x%02x%02x%02x%02x%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);  
            break;
        default:
            sprintf(buffer[buffer_index], "%02x%02x%02x%02x%02x%02x", 
                ether->octet[0], ether->octet[1], ether->octet[2],
                ether->octet[3], ether->octet[4], ether->octet[5]);  
            break;            
    }
    
    return buffer[buffer_index];
}

static int getNetifHwAddr(const char *ifname, etherAddr_t *hwaddr)
{
	int sock, ret;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) 
    {   
        return -1;
    }

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    
	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);

	if(!ret && hwaddr)
    {
        memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, sizeof(etherAddr_t));
    }

	close(sock);
    
	return (ret < 0) ? -1 : 0;
}

static int  getMacAddr( char *pWanHWAddr)
{
 	struct sockaddr hwaddr;
	etherAddr_t addr;
	unsigned char *pMacAddr;
	if (!(getNetifHwAddr(KLINK_IF, &addr)) ) 
	{
	 sprintf(pWanHWAddr, "%s",etherAddrToString(&addr, ETHER_TYPE_NO_SEPARTOR));
	}
	else
	{
		sprintf(pWanHWAddr,"%s","00:00:00:00:00:00");
	}
	return 0;
}

int getSlaveMacNum(cJSON *root)
{
  cJSON *head;
  cJSON *pos;
  cJSON *parameters;
  int slaveNum=0;
  head = cJSON_GetObjectItem(root, "child_devices");
  if(head != NULL)
   {
   for(pos = head->child; pos != NULL; pos = pos->next)
   {
    parameters = cJSON_GetObjectItem(pos, "mac_address");
    if(parameters != NULL)
    {
      slaveNum++;
    }
   }
  }
  else
  {
     TRACE_DEBUG("%s:%d： can't find child_devices.", __FUNCTION__, __LINE__);
  }
  return slaveNum;
}

int getMeshSlaveNumber(cJSON *root)
{
   cJSON *head;
  cJSON *pos;
  cJSON *parameters;
 
  head = cJSON_GetObjectItem(root, "child_devices");
  if(head != NULL)
   {
   for(pos = head->child; pos != NULL; pos = pos->next)
   {
      g_slaveNum++;
      getMeshSlaveNumber(pos);   
   }
  }
 return g_slaveNum;
}
int getMeshNodeNumber()
{
 int slaveNum=0;
 char* out=NULL;
 cJSON *root=NULL; 
 FILE *fp=NULL;
 int read=0;
 int len  = 0;
 int ret=-1;
 char*	line  = NULL;   
 fp = fopen("/tmp/topology_json", "r");
 if(fp == NULL)
 {
  TRACE_DEBUG("==>%s_%d:open /tmp/topology_json fail...",__FUNCTION__,__LINE__);
  return 0;
 }
 else
 {
  read = getline(&line, &len, fp);
  fclose(fp);
  if(line) 
  {
   root = cJSON_Parse(line);  
   free(line);    
   if(root==0)
   {
    TRACE_DEBUG("%s_%d: error...\n ",__FUNCTION__,__LINE__);
   }
   else
   {
    //slaveNum=getSlaveMacNum(root);
    g_slaveNum=0;
    slaveNum=getMeshSlaveNumber(root);
   }
  }
  else
  {
    return ret;
  } 

 }
  out = cJSON_Print(root);
 // TRACE_DEBUG("==>%s_%d:out=\n%s\n\n",__FUNCTION__,__LINE__,out);	
  cJSON_Delete(root);
  free(out);
  return slaveNum;
}

KlinkNode_t getMibInfo(char* sourceValue)
 {
    char *p;
    char *buff;
	int ret=0;
    int i=0;
	KlinkNode_t klinkNodeData;
	memset(&klinkNodeData,0,sizeof(KlinkNode_t));
    buff=sourceValue;  
    p = strsep(&buff, ";");
    while(p)
    {
     if(i==0)
	 strcpy(klinkNodeData.slaveDevideInfo.slaveMacAddr,p);
	 if(i==1)
     strcpy(klinkNodeData.slaveDevideInfo.slaveFwVersion,p);
	 if(i==2)
	 strcpy(klinkNodeData.slaveDevideInfo.sn,p);
     p = strsep(&buff, ";");
     i++;
    }
    return klinkNodeData;
}


/*add mode*/
KlinkNode_t* addKlinkNodeData(KlinkNode_t*head,KlinkNode_t *pdata)
{
   KlinkNode_t *phead,*new_node;
   phead=head;

   if(NULL==phead)
   {
	return NULL;	
   }
   else
   { 
	while(phead->next!=NULL)   
	{   
	    /*if found same slave node already in the link list,just update node data*/
	    if(!strcmp(phead->next->slaveDevideInfo.slaveMacAddr,pdata->slaveDevideInfo.slaveMacAddr))
	    {
	     TRACE_DEBUG("==>%s_%d:found same mesh device in the link node list\n",__FUNCTION__,__LINE__);
		 if(strcmp(phead->next->slaveDevideInfo.slaveFwVersion,pdata->slaveDevideInfo.slaveFwVersion))
		 {
		  memset(phead->next->slaveDevideInfo.slaveFwVersion,0,sizeof(phead->next->slaveDevideInfo.slaveFwVersion));
		  strcpy(phead->next->slaveDevideInfo.slaveFwVersion,pdata->slaveDevideInfo.slaveFwVersion);
		 }
		 if(strcmp(phead->next->slaveDevideInfo.sn,pdata->slaveDevideInfo.sn))
		 {
		  memset(phead->next->slaveDevideInfo.sn,0,sizeof(phead->next->slaveDevideInfo.sn));
		  strcpy(phead->next->slaveDevideInfo.sn,pdata->slaveDevideInfo.sn);
		 }
		 return phead;
	    }
		phead=phead->next;		
	}
      /*else add new node to the link list tail*/
	  if(NULL!=(new_node=(KlinkNode_t*)malloc(sizeof(KlinkNode_t))))
	  {
	      strcpy(new_node->slaveDevideInfo.slaveMacAddr,pdata->slaveDevideInfo.slaveMacAddr);
		  strcpy(new_node->slaveDevideInfo.slaveFwVersion,pdata->slaveDevideInfo.slaveFwVersion);	
		  strcpy(new_node->slaveDevideInfo.sn,pdata->slaveDevideInfo.sn);	
		  phead->next=new_node;
		  new_node->next=NULL;
		  TRACE_DEBUG("add list succed :data= %s\n",new_node->slaveDevideInfo.slaveMacAddr);
		  TRACE_DEBUG("add list succed :data= %s\n",new_node->slaveDevideInfo.slaveFwVersion);	
		  TRACE_DEBUG("add list succed :SN= %s\n",new_node->slaveDevideInfo.sn);	
		 return phead;
	  }	   
   }
}

int createMeshLinkList()
{
  char tmpBuf[128]={0};
  char versionInfo[64]={0};
  char sn[32]={0};
  int slaveNum=0;
  int i=1;
  KlinkNode_t klinkNodeData;
  memset(&klinkNodeData,0x00,sizeof(KlinkNode_t));
  slaveNum=getMeshNodeNumber();	 
  if(slaveNum<1)
  {
  	return 0;
  }
  destroyKlinkList(g_pKlinkHeadNode);
  g_pKlinkHeadNode=initKlinkListHead();
  clearKlinkList(g_pKlinkHeadNode);  
  for(i; i<= slaveNum; i++)
  {
     memset(tmpBuf,0x00,sizeof(tmpBuf));
     memset(sn,0x00,sizeof(sn));
	 memset(versionInfo,0x00,sizeof(versionInfo));
   switch(i)
   {
	case SLAVE1:
	 apmib_get(MIB_KLINK_SLAVE1_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE1_SN, (void *)sn);
	 break;
	case SLAVE2:
	 apmib_get(MIB_KLINK_SLAVE2_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE2_SN, (void *)sn);
	 break;
	case SLAVE3:
	 apmib_get(MIB_KLINK_SLAVE3_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE3_SN, (void *)sn);
	 break;
	case SLAVE4:
	 apmib_get(MIB_KLINK_SLAVE4_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE4_SN, (void *)sn);
	 break;
	case SLAVE5:
	 apmib_get(MIB_KLINK_SLAVE5_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE5_SN, (void *)sn);
	 break;
	case SLAVE6:
	 apmib_get(MIB_KLINK_SLAVE6_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE6_SN, (void *)sn);
	 break;
	case SLAVE7:
	 apmib_get(MIB_KLINK_SLAVE7_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE7_SN, (void *)sn);
	 break;
	case SLAVE8:
	 apmib_get(MIB_KLINK_SLAVE8_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE8_SN, (void *)sn);
	 break;
	case SLAVE9:
	 apmib_get(MIB_KLINK_SLAVE9_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE9_SN, (void *)sn);
	 break;
	case SLAVE10:
	 apmib_get(MIB_KLINK_SLAVE10_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE10_SN, (void *)sn);
	 break;
	case SLAVE11:
	 apmib_get(MIB_KLINK_SLAVE11_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE11_SN, (void *)sn);
	 break;
	case SLAVE12:
	 apmib_get(MIB_KLINK_SLAVE12_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE12_SN, (void *)sn);
	 break;
	case SLAVE13:
	 apmib_get(MIB_KLINK_SLAVE13_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE13_SN, (void *)sn);
	 break;
	case SLAVE14:
	 apmib_get(MIB_KLINK_SLAVE14_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE14_SN, (void *)sn);
	 break;
	case SLAVE15:
	 apmib_get(MIB_KLINK_SLAVE15_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE15_SN, (void *)sn);
	 break;
	case SLAVE16:
	 apmib_get(MIB_KLINK_SLAVE16_SOFT_VERSION, (void *)versionInfo);
	 break;
	default:
	 TRACE_DEBUG("%s_%d:index error,index numbre is %d \n",__FUNCTION__,__LINE__,i);    
	 break;
	}

    sprintf(tmpBuf,"%s;%s;",versionInfo,sn);
    klinkNodeData=getMibInfo(tmpBuf);
    //TRACE_DEBUG("%s_%s_%d:slaveMacAddr=%s fw=%s sn=%s\n",__FILE__,__FUNCTION__,__LINE__,klinkNodeData.slaveDevideInfo.slaveMacAddr,klinkNodeData.slaveDevideInfo.slaveFwVersion,klinkNodeData.slaveDevideInfo.sn);
	addKlinkNodeData(g_pKlinkHeadNode,&klinkNodeData);
   
  }
}

 
/*search target node*/

 KlinkNode_t* serchTargetNode(KlinkNode_t*head,KlinkNode_t *pdata)
{
	KlinkNode_t *phead=head;
	if(phead==NULL)
	{
		TRACE_DEBUG("head_node is empty\n");
		return NULL;
	}

	while(strcmp(phead->slaveDevideInfo.slaveMacAddr,pdata->slaveDevideInfo.slaveMacAddr)&&phead->next!=NULL)
	{    
		phead=phead->next;
	}
	if(!(strcmp(phead->slaveDevideInfo.slaveMacAddr,pdata->slaveDevideInfo.slaveMacAddr)))
	{
		//TRACE_DEBUG("%s_%d:serch succed klink node data=%s\n",__FUNCTION__,__LINE__,phead->slaveDevideInfo.slaveMacAddr);
		//TRACE_DEBUG("%s_%d:serch succed klink node data=%s\n",__FUNCTION__,__LINE__,phead->slaveDevideInfo.sn);
		return phead;
	}
	else
	{
		TRACE_DEBUG("serch failed\n");
		return NULL;
	}
}

KlinkNode_t* serchKlinkListNode_1(KlinkNode_t*head,char *pMac)
{
	KlinkNode_t *phead=head;
	if(phead==NULL)
	{
		TRACE_DEBUG("head_node is empty\n");
		return NULL;
	}
	while(strcmp(phead->slaveDevideInfo.slaveMacAddr,pMac)&&phead->next!=NULL)
	{   
	    TRACE_DEBUG("%s_%d: mac=%s\n ",__FUNCTION__,__LINE__,pMac);
		phead=phead->next;
	}
	if(!(strcmp(phead->slaveDevideInfo.slaveMacAddr,pMac)))
	{
		TRACE_DEBUG("serch succed klink node data=%s\n",pMac);
		return phead;
	}
	else
	{
		TRACE_DEBUG("serch failed\n");
	}
}


int findOldDeviceInfo(char targetInfo[], char* mac, int dataType)
{
  char tmpBuf[128]={0};
  char versionInfo[64]={0};
  char slaveFwVersion[18]={0};
  char slaveMacAddr[18]={0};
  char sn[24]={0};
  int i=1;
  char *p=NULL;
  char *buff=NULL;
  int ret=0;
  int j=0;

  for(i; i<= SLAVE_NUM; i++)
  {
     memset(tmpBuf,0x00,sizeof(tmpBuf));
     memset(sn,0x00,sizeof(sn));
	 memset(versionInfo,0x00,sizeof(versionInfo));
	 memset(slaveMacAddr,0x00,sizeof(slaveMacAddr));
	 memset(slaveFwVersion,0x00,sizeof(slaveFwVersion));
   switch(i)
   {
	case SLAVE1:
	 apmib_get(MIB_KLINK_SLAVE1_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE1_SN, (void *)sn);
	 break;
	case SLAVE2:
	 apmib_get(MIB_KLINK_SLAVE2_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE2_SN, (void *)sn);
	 break;
	case SLAVE3:
	 apmib_get(MIB_KLINK_SLAVE3_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE3_SN, (void *)sn);
	 break;
	case SLAVE4:
	 apmib_get(MIB_KLINK_SLAVE4_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE4_SN, (void *)sn);
	 break;
	case SLAVE5:
	 apmib_get(MIB_KLINK_SLAVE5_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE5_SN, (void *)sn);
	 break;
	case SLAVE6:
	 apmib_get(MIB_KLINK_SLAVE6_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE6_SN, (void *)sn);
	 break;
	case SLAVE7:
	 apmib_get(MIB_KLINK_SLAVE7_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE7_SN, (void *)sn);
	 break;
	case SLAVE8:
	 apmib_get(MIB_KLINK_SLAVE8_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE8_SN, (void *)sn);
	 break;
	case SLAVE9:
	 apmib_get(MIB_KLINK_SLAVE9_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE9_SN, (void *)sn);
	 break;
	case SLAVE10:
	 apmib_get(MIB_KLINK_SLAVE10_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE10_SN, (void *)sn);
	 break;
	case SLAVE11:
	 apmib_get(MIB_KLINK_SLAVE11_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE11_SN, (void *)sn);
	 break;
	case SLAVE12:
	 apmib_get(MIB_KLINK_SLAVE12_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE12_SN, (void *)sn);
	 break;
	case SLAVE13:
	 apmib_get(MIB_KLINK_SLAVE13_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE13_SN, (void *)sn);
	 break;
	case SLAVE14:
	 apmib_get(MIB_KLINK_SLAVE14_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE14_SN, (void *)sn);
	 break;
	case SLAVE15:
	 apmib_get(MIB_KLINK_SLAVE15_SOFT_VERSION, (void *)versionInfo);
	 apmib_get(MIB_KLINK_SLAVE15_SN, (void *)sn);
	 break;
	case SLAVE16:
	 apmib_get(MIB_KLINK_SLAVE16_SOFT_VERSION, (void *)versionInfo);
	 break;
	default:
	 TRACE_DEBUG("%s_%d:index error,index numbre is %d \n",__FUNCTION__,__LINE__,i);    
	 break;
	}
    if(strlen(versionInfo)==0)
		break;
    sprintf(tmpBuf,"%s;%s;",versionInfo,sn);
    buff=tmpBuf;  
    p = strsep(&buff, ";");
    while(p)
    {
     if(j==0)
	 strcpy(slaveMacAddr,p);
	 if(j==1)
     strcpy(slaveFwVersion,p);
	 if(j==2)
	 strcpy(sn,p);
     p = strsep(&buff, ";");
     i++;
    }
    if(strncmp(slaveMacAddr,mac,sizeof(slaveMacAddr))==0)
    {
      if(DEVICE_INFO_VERSION==dataType)
      {
       strcpy(targetInfo,slaveFwVersion);
      }
      else if(DEVICE_INFO_SN==dataType)
      {
       strcpy(targetInfo,sn);	
      }
	  ret = FOUND_TARGET_SUCC;
	  return ret;
    } 
  }
  return ret;
}

int getSlaveVersion(char targetInfo[], char* mac, int dataType)
{

 char *pMac=mac;
 KlinkNode_t *pTargetVersion=NULL;
 KlinkNode_t data;
 int ret=0;
 char sn[24]={0};
 static char masterMac[17]={0};
 memset(&data,0x00,sizeof(KlinkNode_t));
 getMacAddr(masterMac);
 if(strncmp(masterMac,mac,strlen(masterMac))==0)
 {
   if(DEVICE_INFO_VERSION==dataType)
    {
     strcpy(targetInfo,fwVersion);
    }
    else if(DEVICE_INFO_SN==dataType)
    {
     apmib_get(MIB_CUSTOMER_HW_SERIAL_NUM, sn);
     strcpy(targetInfo,sn);	
    }
  return FOUND_TARGET_SUCC;
} 
 strcpy(data.slaveDevideInfo.slaveMacAddr,pMac);
 createMeshLinkList();
 pTargetVersion=serchTargetNode(g_pKlinkHeadNode,&data);


 if(pTargetVersion!=NULL)
 {
     if(DEVICE_INFO_VERSION==dataType)
     {
        strcpy(targetInfo,pTargetVersion->slaveDevideInfo.slaveFwVersion);
     }
     else if(DEVICE_INFO_SN==dataType)
     {
       strcpy(targetInfo,pTargetVersion->slaveDevideInfo.sn);	
     }
 }
 else
 {
  strcpy(targetInfo,"----");
 #if 0
    ret=findOldDeviceInfo( targetInfo, mac,dataType);
    if(ret)
    {
     ;
    }
     else
    {
      if(DEVICE_INFO_VERSION==dataType)
      {
         strcpy(targetInfo,fwVersion);
		 ret=FOUND_TARGET_SUCC;
      }
      else if(DEVICE_INFO_SN==dataType)
      {
       apmib_get(MIB_CUSTOMER_HW_SERIAL_NUM, sn);
       strcpy(targetInfo,sn);	
	   ret = FOUND_TARGET_SUCC;
      }
    }
#endif
 }
 return ret;
}




