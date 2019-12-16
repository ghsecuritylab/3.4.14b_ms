#include <stdio.h>
#include <stdlib.h>
#include <time.h>
/* System include files */
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ctype.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <time.h>
#include <sys/wait.h> 
#include <net/if_arp.h> 
#include <arpa/inet.h> 

#include "../boa/apmib/apmib.h"
#include "../boa/src/deviceProcIf.h"

#include "../boa/src/cJSON.h"

#define MIB_MAP_CONTROLLER         2386
#define MIB_MAP_CONFIGURED_BAND    2387
#define MIB_WLAN_MAP_BSS_TYPE      2388
#define MIB_MAP_DEVICE_NAME        2389
#define MAX_MAP_DEVICE_NAME_LEN    30

typedef enum { IP_ADDR, DST_IP_ADDR, SUBNET_MASK, DEFAULT_GATEWAY, HW_ADDR } ADDR_T;
#define RTF_UP			0x0001          //route usable
#define RTF_GATEWAY		0x0002          //destination is a gateway
#define _PATH_PROCNET_ROUTE	"/proc/net/route"
//changes in following table should be synced to MCS_DATA_RATEStr[] in 8190n_proc.c



#define IFACE_FLAG_T 0x01
#define IP_ADDR_T 0x02
#define NET_MASK_T 0x04
#define HW_ADDR_T 0x08
#define HW_NAT_LIMIT_NETMASK 0xFFFFFF00 //for arp table 512 limitation,

#define ARP_TABLE_MAX_NUM 256
#define _PATH_DHCPS_LEASES	"/var/lib/misc/udhcpd.leases"
#define _PATH_DHCPS_PID	"/var/run/udhcpd.pid" 
#define _PATH_DEVICE_MAC_BRAND "/etc/device_mac_brand.txt"
#define MAC_BCAST_ADDR		(unsigned char *) "\xff\xff\xff\xff\xff\xff"
#define IP_ADDR_T 0x02
#define HW_ADDR_T 0x08

#define APP_HTTP_ERR 		1001	//协议头部错误
#define APP_JSON_ERR 		1002	//JSON格式错误
#define APP_GETTING_ERR 	1003	//获取配置失败
#define APP_SETTING_SUC 	1004	//设置配置成功
#define APP_SETTING_ERR 	1005	//设置配置错误
#define APP_CHILD_UPGRADE 	1006	//子设备开始升级提醒
#define APP_SAME_GROUP		1007	//家长控制分组相同报错

#define MAX_L2_LIST_NUM    256

typedef struct app_wl_sta_info 
{
	unsigned char rssi;
	unsigned long tx_rate;
	unsigned long rx_rate;

	unsigned char addr[32];
	unsigned char model[32];
	unsigned char link_time[64];
	
} APP_WL_STA_INFO_T, *APP_WL_STA_INFO_Tp;

typedef struct app_wl_info
{
	int sta_num;
	struct app_wl_sta_info sta_info[256];
}APP_WL_INFO_T,*APP_WL_INFO_Tp;

typedef struct rtk_lan_device_info{
	unsigned char hostname[64];
	unsigned int ip;
	unsigned char mac[6];
	unsigned int expires;
	unsigned char conType;
	unsigned char brand[16];
	unsigned char on_link;
	//get from proc/rtl865x/asicCounter
	unsigned int rx_bytes;
	unsigned int tx_bytes;

    unsigned char slave_flg;    //device link in mesh slave
    unsigned int rx_speed;      
    unsigned int tx_speed;
    unsigned char	rssi;
	unsigned int linktime;		//link time
	
}RTK_LAN_DEVICE_INFO_T, *RTK_LAN_DEVICE_INFO_Tp;

enum LAN_LINK_TYPE {
	RTK_LINK_ERROR =0,
	RTK_ETHERNET,
	RTK_WIRELESS_5G,
	RTK_WIRELESS_2G
};

typedef struct rtk_arp_entry{	
	unsigned int ip;
	unsigned char mac[6];	
}RTK_ARP_ENTRY_T, *RTK_ARP_ENTRY_Tp;
#define ARP_TABLE_MAX_NUM 256
struct rtk_dhcp_client_info {
	unsigned char hostname[64];
	unsigned int ip;
	unsigned char mac[6];
	unsigned int expires;
	unsigned int linktime;
};
typedef struct rtk_l2Info_{
	unsigned char mac[6];
	int portNum;
} rtk_l2Info;
typedef struct rtk_asicConterInfo_{
	unsigned int rxBytes;
	unsigned int txBytes;
} rtk_asicConterInfo;
#define SSID_LEN 32

typedef struct _bss_info {
    unsigned char state;
    unsigned char channel;
    unsigned char txRate;
    unsigned char bssid[6];
    unsigned char rssi, sq;	// RSSI  and signal strength
    unsigned char ssid[SSID_LEN+1];
} bss_info;

/* Macro definition */
static int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}
/*
  *@name rtk_get_device_brand
  *@ input 
     mac , the pointer of lan device mac address 
     mac_file , contains the prefix mac and brand list, such as "/etc/device_mac_brand.txt"
  *@output
     brand ,  hold the brand of device, such as Apple, Samsung, Xiaomi, Nokia, Huawei, etc.
  *@ return value
  	RTK_SUCCESS
  	RTK_FAILED
  *
  */
int rtk_get_device_brand(unsigned char *mac, char *mac_file, char *brand)
{		
	FILE *fp;
	int index;
	unsigned char prefix_mac[16], mac_brand[64];
	char *pchar;
	int found=0;
	if(mac==NULL || mac_file==NULL || brand==NULL)
		return -1;
	if((fp= fopen(mac_file, "r"))==NULL)
		return -1;

	sprintf(prefix_mac, "%02X-%02X-%02X", mac[0], mac[1], mac[2]);

	for(index = 0 ; index < 8; ++index)
	{
		if((prefix_mac[index]  >= 'a')  && (prefix_mac[index]<='f'))
			prefix_mac[index] -= 32;
	}

	//printf("%s.%d. str(%s)\n",__FUNCTION__,__LINE__,prefix_mac);

	while(fgets(mac_brand, sizeof(mac_brand), fp))
	{			
		mac_brand[strlen(mac_brand)-1]='\0';		
		if((pchar=strstr(mac_brand, prefix_mac))!=NULL)
		{
			pchar+=9;
			strcpy(brand, pchar);
			found=1;
			break;
		}
	}
	fclose(fp);
	
	if(found==1)
		return 0;
	
	return -1;
}

static int getDhcpClient(char **ppStart, unsigned long *size, unsigned char *hname, unsigned int *ip, unsigned char *mac, unsigned int *lease, unsigned int *linktime)
{
	struct dhcpOfferedAddr 
	{
		unsigned char chaddr[16];
		unsigned int yiaddr;       /* network order */
		unsigned int expires;      /* host order */		
		unsigned int linktime; /* link time */
//#if defined(CONFIG_RTL8186_KB) || defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
		char hostname[64]; /* Brad add for get hostname of client */
		u_int32_t isUnAvailableCurr;	/* Brad add for WEB GUI check */
//#endif
	};

	struct dhcpOfferedAddr entry;
	unsigned char empty_haddr[16]; 

	memset(empty_haddr, 0, 16); 
	//printf("%s:%d size=%d\n",__FUNCTION__,__LINE__,*size);
	if ( *size < sizeof(entry) )
		return -1;

	entry = *((struct dhcpOfferedAddr *)*ppStart);
	*ppStart = *ppStart + sizeof(entry);
	*size = *size - sizeof(entry);
	//printf("%s:%d expires=%d\n",__FUNCTION__,__LINE__,entry.expires);

	if (entry.expires == 0)
		return 0;
	//printf("%s:%d\n",__FUNCTION__,__LINE__);

	if(!memcmp(entry.chaddr, empty_haddr, 16))
		return 0;

	//strcpy(ip, inet_ntoa(*((struct in_addr *)&entry.yiaddr)) );
	*ip=entry.yiaddr;
	memcpy(mac, entry.chaddr, 6);
	
	//snprintf(mac, 20, "%02x:%02x:%02x:%02x:%02x:%02x",entry.chaddr[0],
	//	entry.chaddr[1],entry.chaddr[2],entry.chaddr[3],entry.chaddr[4], entry.chaddr[5]);
	//if(entry.expires == 0xffffffff)
	//	sprintf(liveTime,"%s", "Always");
	//else
	//	snprintf(liveTime, 10, "%lu", (unsigned long)ntohl(entry.expires));
	*lease=entry.expires;
	*linktime=entry.linktime;
	
	
	if(entry.hostname[0])
	{
		strcpy(hname, entry.hostname);
	}
	
	return 1;
}

/*
  *@name rtk_get_dhcp_client_list
  *@ input 
     rtk_dhcp_client_info *, the pointer of lan dhcp client list which specific every client info, such as host name, ip, mac, lease time 
  *@output
     num , unsigned int *, which hold the num of dhcp client.
  *@ return value
  	RTK_SUCCESS
  	RTK_FAILED
  *
  */
  int getPid(char *filename)
{
	struct stat status;
	char buff[100];
	FILE *fp;

	if ( stat(filename, &status) < 0)
		return -1;
	fp = fopen(filename, "r");
	if (!fp) {
        	fprintf(stderr, "Read pid file error!\n");
		return -1;
   	}
	fgets(buff, 100, fp);
	fclose(fp);

	return (atoi(buff));
}
int rtk_get_dhcp_client_list(unsigned int *num, struct rtk_dhcp_client_info *pclient)
{	
	FILE *fp;
	int idx=0, ret;
	char *buf=NULL, *ptr, tmpBuf[100];
	unsigned int ip, lease, linktime;
	unsigned char mac[6], hostname[64]={0};

	struct stat status;
	int pid;
	unsigned long fileSize=0;
	// siganl DHCP server to update lease file
	pid = getPid(_PATH_DHCPS_PID);
	snprintf(tmpBuf, 100, "kill -SIGUSR1 %d\n", pid);

	if ( pid > 0)
		system(tmpBuf);

	usleep(1000);

	if ( stat(_PATH_DHCPS_LEASES, &status) < 0 )
		goto err;

	fileSize=status.st_size;
	buf = malloc(fileSize);
	if ( buf == NULL )
		goto err;
	fp = fopen(_PATH_DHCPS_LEASES, "r");
	if ( fp == NULL )
		goto err;

	fread(buf, 1, fileSize, fp);
	fclose(fp);

	ptr = buf;
	while (1) 
	{
		memset(hostname, 0, sizeof(hostname));
		ret = getDhcpClient(&ptr, &fileSize, hostname, &ip, mac, &lease, &linktime);
		//printf("%s:%d ret=%d, hostname = %s\n",__FUNCTION__,__LINE__,ret, hostname);

		if (ret < 0)
			break;
		if (ret == 0)
			continue;

		strcpy(pclient[idx].hostname, hostname);
		pclient[idx].ip=ip;
		memcpy(pclient[idx].mac, mac, 6);
		pclient[idx].expires=lease;
		pclient[idx].linktime=linktime;
		
//		printf("%s:%d pclient[%d].expires=%d\n",__FUNCTION__,__LINE__,idx,pclient[idx].expires);
	//	if(strcmp(pclient[idx].hostname, "null")==0)
		//	strcpy(pclient[idx].hostname, pclient[idx].brand);
		
		idx++;
		if(idx>=MAX_STA_NUM)
			return -1;
	}
	
err:
	*num=idx;
	if (buf)
		free(buf);
	
	return 0;
}

static int string_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;

		key[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
	}
	return 1;
}

int get_arp_table_list(char *filename, RTK_ARP_ENTRY_Tp parplist)
{
	FILE *fp;
	char line_buffer[512];	
	char mac_str[13], tmp_mac_str[18];
	char ip_str[16], if_name[16];
	unsigned char mac_addr[6];
	int idx=0, i, j;	
	char *pchar, *pstart, *pend;
	struct in_addr ip_addr;

	if(filename==NULL || parplist==NULL)
		return -1; 
	if((fp= fopen(filename, "r"))==NULL)
		return -1;
	
	while(fgets(line_buffer, sizeof(line_buffer), fp))
	{			
		line_buffer[strlen(line_buffer)-1]='\0';		

		sscanf(line_buffer,"%s %*s %*s %s %*s %s",ip_str,tmp_mac_str,if_name);
		if(strcmp(if_name, "br0")!=0)
			continue;

		inet_aton(ip_str, &ip_addr);
		parplist[idx].ip=ip_addr.s_addr;
		
		for(i=0, j=0; i<17 && j<12; i++)
		{
			if(tmp_mac_str[i]!=':')
			{
				mac_str[j++]=tmp_mac_str[i];
			}
		}
		mac_str[12]=0;			
			
		if (strlen(mac_str)==12 && string_to_hex(mac_str, mac_addr, 12)) 
		{
			memcpy(parplist[idx].mac, mac_addr, 6);
			idx++;
		}		
	}
	fclose(fp);
	return idx;		
}

/********************************************************
** get dst mac index, if not exist, add the mac to (the end of) arrary
*********************************************************/
int getDstMacIdx(RTK_LAN_DEVICE_INFO_Tp pdevinfo,unsigned char mac[6],int max_num)
{
	int i=0;
	char mac_null[6]={0};
	
	for(i=0;i<max_num;i++)
	{
		if(memcmp(pdevinfo[i].mac,mac,6)==0)
		{
			//printf("%s:%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",__FUNCTION__,__LINE__,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
			return i;
		}
		if(memcmp(pdevinfo[i].mac,mac_null,6)==0)
		{
			//printf("%s:%d\n",__FUNCTION__,__LINE__);
			memcpy(pdevinfo[i].mac,mac,6);
			return i;
		}
	}
	return max_num;
}

/*
        get port status info by proc/rtl865x/asicCounter
*/
void GetPortStatus(int port_number,rtk_asicConterInfo *info)
{
        /*fill cur_rx /cur_tx parememter */
        FILE *fp=NULL;
        int  line_cnt =0;
        unsigned char buffer[128];
        //system("cat /proc/rtl865x/asicCounter  > /var/tmpResult");    

        //if((fp = fopen("/var/tmpResult","r+")) != NULL)
        if((fp = fopen("/proc/rtl865x/asicCounter","r+")) != NULL)
        {
                while(fgets(buffer, 128, fp))
                {
                        line_cnt++;
                        if(line_cnt == 12*port_number+3)        //update receive bytes
                        {
                                sscanf(buffer," Rcv %u ",&(info->rxBytes));
                        }

                        if(line_cnt == 12*port_number+10)       //update send bytes
                        {
                                sscanf(buffer," Snd %u ",&(info->txBytes));
                                fclose(fp);
                                return ;
                        }
                }
        }
        fclose(fp);
}

int get_info_from_l2_tab(char *filename, rtk_l2Info l2list[])
{
	FILE *fp;
	char line_buffer[512];	
	char mac_str[13];
	unsigned char mac_addr[6];
	int idx=0, i, j;	
	char *pchar, *pstart;
	
	unsigned char br0_mac[6];
	unsigned char br0_mac_str[32];
	
	if(filename==NULL)
		return -1; 
	if((fp= fopen(filename, "r"))==NULL)
		return -1;
	
	memset(br0_mac,0,6);
	apmib_get(MIB_ELAN_MAC_ADDR,  (void *)br0_mac);
	if(!memcmp(br0_mac, "\x00\x00\x00\x00\x00\x00", 6))
		apmib_get(MIB_HW_NIC0_ADDR,  (void *)br0_mac);
	
	sprintf(br0_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", br0_mac[0], br0_mac[1], br0_mac[2], br0_mac[3], br0_mac[4], br0_mac[5]);
	br0_mac_str[strlen("ff:ff:ff:ff:ff:ff")]='\0';
	
	while(fgets(line_buffer, sizeof(line_buffer), fp))
	{			
		line_buffer[strlen(line_buffer)-1]='\0';

		if(strstr(line_buffer, "ff:ff:ff:ff:ff:ff") || strstr(line_buffer, "CPU") || strstr(line_buffer, "FID:1") || strstr(line_buffer, br0_mac_str))
			continue;	
        
		pchar=strchr(line_buffer, ':');
		pstart=pchar-2;
		for(i=0, j=0; i<17 && j<12; i++)
		{
			if(pstart[i]!=':')
			{
				mac_str[j++]=pstart[i];
			}
		}
		mac_str[j]=0;
		if (strlen(mac_str)==12 && string_to_hex(mac_str, mac_addr, 12)) 
		{
			memcpy(l2list[idx].mac, mac_addr, 6);
			
			pchar=strstr(line_buffer,"mbr");
			sscanf(pchar,"mbr(%d",&(l2list[idx].portNum));
			
			idx++;
            if(idx >= MAX_L2_LIST_NUM)
                break;
		}		
	}
	fclose(fp);
	return idx;		
}
static inline int
iw_get_ext(int                  skfd,           /* Socket to the kernel */
           char *               ifname,         /* Device name */
           int                  request,        /* WE ID */
           struct iwreq *       pwrq)           /* Fixed part of the request */
{
  /* Set device name */
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  /* Do the request */
  return(ioctl(skfd, request, pwrq));
}


/////////////////////////////////////////////////////////////////////////////
int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo )
{
#ifndef NO_ACTION
    int skfd=0;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0){
      /* If no wireless name : no wireless extensions */
      close( skfd );
        return -1;
	}
    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1);
    memset(pInfo, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));

    if (iw_get_ext(skfd, interface, SIOCGIWRTLSTAINFO, &wrq) < 0){
    	close( skfd );
		return -1;
	}
    close( skfd );
#else
    return -1;
#endif
    return 0;
}


/////////////////////////////////////////////////////////////////////////////
int getInAddr( char *interface, ADDR_T type, void *pAddr )
{
    struct ifreq ifr;
    int skfd=0, found=0;
    struct sockaddr_in *addr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return 0;
		
    strcpy(ifr.ifr_name, interface);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
    	close( skfd );
		return (0);
	}
    if (type == HW_ADDR) {
    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(pAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
		found = 1;
	}
    }
    else if (type == IP_ADDR) {
	if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }
    else if (type == SUBNET_MASK) {
	if (ioctl(skfd, SIOCGIFNETMASK, &ifr) >= 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }
	else if (type == DST_IP_ADDR)
	{
		if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) >= 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
	}
    close( skfd );
    return found;

}


/*
  *@name rtk_get_lan_device_info
  *@ input 
     pdevinfo , the pointer of lan device info
     MAX_NUM, the max number of lan device, should be MAX_STA_NUM+1
  *@output
     num ,  hold the lan device number
  *@ return value
  	-1:fail
  	0:ok
  *
  */
int rtk_get_lan_device_info(unsigned int *num, RTK_LAN_DEVICE_INFO_Tp pdevinfo,int max_num)
{	
	int l2_tab_num=0,i=0,wifi_sta_num=0,arp_entry_num=0,dhcp_device_num=0,devInfoIdx=0;
	rtk_l2Info l2list[MAX_L2_LIST_NUM]={0};
	rtk_asicConterInfo asicConInfo={0};
	WLAN_STA_INFO_T wlanStaList[MAX_STA_NUM]={0};
	RTK_ARP_ENTRY_T arp_tab[ARP_TABLE_MAX_NUM]={0};
	struct in_addr lan_addr;
    struct sockaddr hwaddr;
	unsigned char lan_mac[6];
	struct rtk_dhcp_client_info dhcp_client_info[MAX_STA_NUM+1]={0};
	char mac_null[6]={0};
	int devNum=0,ret=0;
	
	if(num==NULL || pdevinfo==NULL || max_num<MAX_STA_NUM)
		return -1;
	bzero(pdevinfo,sizeof(RTK_LAN_DEVICE_INFO_T)*max_num);


	getInAddr("br0", IP_ADDR_T, (void *)&lan_addr);
    getInAddr("br0", HW_ADDR_T, (void *)&hwaddr);
    memcpy(lan_mac, hwaddr.sa_data, 6);

//l2 table
	l2_tab_num=get_info_from_l2_tab("/proc/rtl865x/l2", l2list);
	for(i=0;i<l2_tab_num;i++)
	{//assign all mac in pdevinfo, get mac index. if mac not exist, add it to pdevinfo arrary
		devInfoIdx=getDstMacIdx(pdevinfo,l2list[i].mac,MAX_STA_NUM);	
		//printf("%s:%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",__FUNCTION__,__LINE__,maclist[i][0],maclist[i][1],maclist[i][2],maclist[i][3],maclist[i][4],maclist[i][5]);
		if(devInfoIdx < MAX_STA_NUM)
		{
    		pdevinfo[devInfoIdx].conType=RTK_ETHERNET;

    		GetPortStatus(l2list[i].portNum,&asicConInfo);
    		pdevinfo[devInfoIdx].tx_bytes=asicConInfo.rxBytes;
    		pdevinfo[devInfoIdx].rx_bytes=asicConInfo.txBytes;	
            pdevinfo[devInfoIdx].rssi = 100;
            pdevinfo[devInfoIdx].rx_speed = 0;
            pdevinfo[devInfoIdx].tx_speed = 0;
		}
	}
//	printf("%s:%d \n",__FUNCTION__,__LINE__);
	
//wlan0
	//printf("sizeof maclist=%d\n",sizeof(maclist));
	bzero(wlanStaList,sizeof(wlanStaList));
	getWlStaInfo("wlan0", wlanStaList);
	for(i=0;i<MAX_STA_NUM;i++)
	{
		if(wlanStaList[i].aid && (wlanStaList[i].flag & STA_INFO_FLAG_ASOC))
		{
		
			devInfoIdx=getDstMacIdx(pdevinfo,wlanStaList[i].addr,MAX_STA_NUM);	
            if(devInfoIdx < MAX_STA_NUM)
		    {
#if defined(CONFIG_RTL_92D_SUPPORT)
			    pdevinfo[devInfoIdx].conType=RTK_WIRELESS_5G;
#else
			    pdevinfo[devInfoIdx].conType=RTK_WIRELESS_2G;
#endif
			    pdevinfo[devInfoIdx].on_link=1;
			    pdevinfo[devInfoIdx].tx_bytes=wlanStaList[i].rx_bytes;
			    pdevinfo[devInfoIdx].rx_bytes=wlanStaList[i].tx_bytes;
                pdevinfo[devInfoIdx].rssi = wlanStaList[i].rssi;
                pdevinfo[devInfoIdx].rx_speed = wlanStaList[i].RxOperaRate;
                pdevinfo[devInfoIdx].tx_speed = wlanStaList[i].txOperaRates;
            }
		}
	}

    bzero(wlanStaList,sizeof(wlanStaList));
	getWlStaInfo("wlan0-va1", wlanStaList);
	for(i=0;i<MAX_STA_NUM;i++)
	{
		if(wlanStaList[i].aid && (wlanStaList[i].flag & STA_INFO_FLAG_ASOC))
		{
			devInfoIdx=getDstMacIdx(pdevinfo,wlanStaList[i].addr,MAX_STA_NUM);	
            if(devInfoIdx < MAX_STA_NUM)
		    {
#if defined(CONFIG_RTL_92D_SUPPORT)
			    pdevinfo[devInfoIdx].conType=RTK_WIRELESS_5G;
#else
			    pdevinfo[devInfoIdx].conType=RTK_WIRELESS_2G;
#endif
			    pdevinfo[devInfoIdx].on_link=1;
			    pdevinfo[devInfoIdx].tx_bytes=wlanStaList[i].rx_bytes;
			    pdevinfo[devInfoIdx].rx_bytes=wlanStaList[i].tx_bytes;
                pdevinfo[devInfoIdx].rssi = wlanStaList[i].rssi;
                pdevinfo[devInfoIdx].rx_speed = wlanStaList[i].RxOperaRate;
                pdevinfo[devInfoIdx].tx_speed = wlanStaList[i].txOperaRates;
            }
		}
	}
	
#if defined(CONFIG_RTL_92D_SUPPORT)
//wlan1
	bzero(wlanStaList,sizeof(wlanStaList));
	getWlStaInfo("wlan1", wlanStaList);
	for(i=0;i<MAX_STA_NUM;i++)
	{
		if(wlanStaList[i].aid && (wlanStaList[i].flag & STA_INFO_FLAG_ASOC))
		{
			devInfoIdx=getDstMacIdx(pdevinfo,wlanStaList[i].addr,MAX_STA_NUM);
			
            if(devInfoIdx < MAX_STA_NUM)
		    {
    			pdevinfo[devInfoIdx].conType=RTK_WIRELESS_2G;
    			pdevinfo[devInfoIdx].on_link=1;
    			pdevinfo[devInfoIdx].tx_bytes=wlanStaList[i].rx_bytes;
    			pdevinfo[devInfoIdx].rx_bytes=wlanStaList[i].tx_bytes;
                pdevinfo[devInfoIdx].rssi = wlanStaList[i].rssi;
                pdevinfo[devInfoIdx].rx_speed = wlanStaList[i].RxOperaRate;
                pdevinfo[devInfoIdx].tx_speed = wlanStaList[i].txOperaRates;
            }
		}
	}

    bzero(wlanStaList,sizeof(wlanStaList));
	getWlStaInfo("wlan1-va1", wlanStaList);
	for(i=0;i<MAX_STA_NUM;i++)
	{
		if(wlanStaList[i].aid && (wlanStaList[i].flag & STA_INFO_FLAG_ASOC))
		{
			devInfoIdx=getDstMacIdx(pdevinfo,wlanStaList[i].addr,MAX_STA_NUM);
            if(devInfoIdx < MAX_STA_NUM)
		    {
    			pdevinfo[devInfoIdx].conType=RTK_WIRELESS_2G;
    			pdevinfo[devInfoIdx].on_link=1;
    			pdevinfo[devInfoIdx].tx_bytes=wlanStaList[i].rx_bytes;
    			pdevinfo[devInfoIdx].rx_bytes=wlanStaList[i].tx_bytes;
                pdevinfo[devInfoIdx].rssi = wlanStaList[i].rssi;
                pdevinfo[devInfoIdx].rx_speed = wlanStaList[i].RxOperaRate;
                pdevinfo[devInfoIdx].tx_speed = wlanStaList[i].txOperaRates;
            }
		}
	}
#endif

//arp table
	arp_entry_num=get_arp_table_list("/proc/net/arp", arp_tab);
	//printf("%s:%d arp_entry_num = %d\n",__FUNCTION__,__LINE__, arp_entry_num);

	for(i=0;i<arp_entry_num;i++)
	{
		devInfoIdx=getDstMacIdx(pdevinfo,arp_tab[i].mac,MAX_STA_NUM);
		//printf("%s:%d devInfoIdx=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",__FUNCTION__,__LINE__,devInfoIdx,
			//arp_tab[i].mac[0],arp_tab[i].mac[1],arp_tab[i].mac[2],arp_tab[i].mac[3],arp_tab[i].mac[4],arp_tab[i].mac[5]);
		if(devInfoIdx < MAX_STA_NUM)
		{
    		pdevinfo[devInfoIdx].ip=arp_tab[i].ip;
    		//printf("%s:%d ip=0x%x\n",__FUNCTION__,__LINE__,pdevinfo[devInfoIdx].ip);
    		if(pdevinfo[devInfoIdx].conType==RTK_ETHERNET)
    		//if(sendArpToCheckDevIsAlive(pdevinfo[devInfoIdx].ip,lan_addr.s_addr, lan_mac)==0)
    			pdevinfo[devInfoIdx].on_link=1;
    		//printf("%s:%d \n",__FUNCTION__,__LINE__);
		}
	}

//dhcp list
	rtk_get_dhcp_client_list(&dhcp_device_num, &dhcp_client_info);
	//printf("%s:%d dhcp_device_num=%d\n",__FUNCTION__,__LINE__,dhcp_device_num);

	for(i=0;i<dhcp_device_num;i++)
	{
		devInfoIdx=getDstMacIdx(pdevinfo,dhcp_client_info[i].mac,MAX_STA_NUM);
        if(devInfoIdx < MAX_STA_NUM)
		{
    		strcpy(pdevinfo[devInfoIdx].hostname,dhcp_client_info[i].hostname);
    		pdevinfo[devInfoIdx].ip=dhcp_client_info[i].ip;
    		pdevinfo[devInfoIdx].expires=dhcp_client_info[i].expires;
			pdevinfo[devInfoIdx].linktime=dhcp_client_info[i].linktime;
        }
	}
	
	devNum=getDstMacIdx(pdevinfo,mac_null,MAX_STA_NUM);
	for(i=0;i<devNum;i++)
	{
		if(!pdevinfo[i].hostname[0])
			strcpy(pdevinfo[i].hostname,"---");
		ret=rtk_get_device_brand(pdevinfo[i].mac, _PATH_DEVICE_MAC_BRAND, pdevinfo[i].brand);
		if(ret<0)
			strcpy(pdevinfo[i].brand,"---");
	}

	*num=devNum;
	return 0;
	
}


cJSON * creatJSONMeshStationOBJ(RTK_LAN_DEVICE_INFO_T *devinfo)
{
    cJSON *obj;
    char buf[512];
    
    obj = cJSON_CreateObject();
    if(obj == NULL)
        return NULL;

    sprintf(buf,"%02x%02x%02x%02x%02x%02x",devinfo->mac[0], devinfo->mac[1], devinfo->mac[2], devinfo->mac[3], devinfo->mac[4], devinfo->mac[5]);
    cJSON_AddStringToObject(obj, "station_mac", buf);
    sprintf(buf, "%d", devinfo->rssi);
    cJSON_AddStringToObject(obj, "station_rssi", buf);
    if(devinfo->conType == RTK_ETHERNET)
    {
        sprintf(buf,"ETHERNET");
    }
    else if(devinfo->conType == RTK_WIRELESS_5G)
    {
        sprintf(buf,"5G");
    }
    else if(devinfo->conType == RTK_WIRELESS_2G)
    {
        sprintf(buf,"2G");
    }
    else
    {
        sprintf(buf,"ERR");
    }
    cJSON_AddStringToObject(obj, "station_connected_band", buf);
    sprintf(buf, "%d", devinfo->rx_speed);
    cJSON_AddStringToObject(obj, "station_downlink", buf);
    sprintf(buf, "%d", devinfo->tx_speed);
    cJSON_AddStringToObject(obj, "station_uplink", buf);

    strcpy(buf,inet_ntoa((*((struct in_addr *)&(devinfo->ip)))));
    cJSON_AddStringToObject(obj, "station_ip", buf);
    cJSON_AddStringToObject(obj, "station_hostname", devinfo->hostname);
    cJSON_AddStringToObject(obj, "station_brand", devinfo->brand);
    cJSON_AddStringToObject(obj, "station_link_time", "null");
#if 0
            {
                "station_mac":"40331a573909",
                "station_rssi":"61",
                "station_connected_band":"5G",
                "station_downlink":"150",
                "station_uplink":"108"
                "station_ip":"192.168.1.10"
                "station_hostname":"mate20"
                "station_brand":"HUAWEI"
                "station_link_time":"68"
            }
    
#endif

    return obj;
}

int getMacIdx(RTK_LAN_DEVICE_INFO_T *devinfo, unsigned char mac[6], int max_num)
{
	int i = 0;

	for(i=0;i<max_num;i++)
	{
		if(memcmp(devinfo[i].mac, mac, 6)== 0)
		{
			return i;
		}
	}
	return max_num;
}
/*
 * Name: to_upper
 *
 * Description: Turns a string into all upper case (for HTTP_ header forming)
 * AND changes - into _
 */

static char *to_upper(char *str)
{
    char *start = str;

    while (*str) {
        if (*str == '-')
            *str = '_';
        else
            *str = toupper(*str);
        str++;
    }

    return start;
}
static int SetWlan_idx(char * wlan_iface_name)
{
	int idx;
	
		idx = atoi(&wlan_iface_name[4]);
		if (idx >= NUM_WLAN_INTERFACE) {
				printf("invalid wlan interface index number!\n");
				return 0;
		}
		wlan_idx = idx;
		vwlan_idx = 0;
	
#ifdef MBSSID		
		
		if (strlen(wlan_iface_name) >= 9 && wlan_iface_name[5] == '-' &&
				wlan_iface_name[6] == 'v' && wlan_iface_name[7] == 'a') {
				idx = atoi(&wlan_iface_name[8]);
				if (idx >= NUM_VWLAN_INTERFACE) {
					printf("invalid virtual wlan interface index number!\n");
					return 0;
				}
				
				vwlan_idx = idx+1;
				idx = atoi(&wlan_iface_name[4]);
				wlan_idx = idx;
		}
#endif	
#ifdef UNIVERSAL_REPEATER
				if (strlen(wlan_iface_name) >= 9 && wlan_iface_name[5] == '-' &&
						!memcmp(&wlan_iface_name[6], "vxd", 3)) {
					vwlan_idx = NUM_VWLAN_INTERFACE;
					idx = atoi(&wlan_iface_name[4]);
					wlan_idx = idx;
				}
	
#endif				
				
return 1;		
}

int getDefaultRoute(char *interface, struct in_addr *route)
{
	char buff[1024], iface[16];
	char gate_addr[128], net_addr[128], mask_addr[128];
	int num, iflags, metric, refcnt, use, mss, window, irtt;
	FILE *fp = fopen(_PATH_PROCNET_ROUTE, "r");
	char *fmt;
	int found=0;
	unsigned long addr;

	if (!fp) {
       		printf("Open %s file error.\n", _PATH_PROCNET_ROUTE);
		return 0;
    	}

	fmt = "%16s %128s %128s %X %d %d %d %128s %d %d %d";

	while (fgets(buff, 1023, fp)) {
		num = sscanf(buff, fmt, iface, net_addr, gate_addr,
		     		&iflags, &refcnt, &use, &metric, mask_addr, &mss, &window, &irtt);
		if (num < 10 || !(iflags & RTF_UP) || !(iflags & RTF_GATEWAY) || strcmp(iface, interface))
	    		continue;
		sscanf(gate_addr, "%lx", &addr );
		*route = *((struct in_addr *)&addr);

		found = 1;
		break;
	}

    	fclose(fp);
    	return found;
}

int getWispRptIface(char**pIface,int wlanId)
{
	int rptEnabled=0,wlanMode=0,opMode=0;
	char wlan_wanIfName[16]={0};
	if(wlanId == 0)
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&rptEnabled);
	else if(1 == wlanId)
		apmib_get(MIB_REPEATER_ENABLED2, (void *)&rptEnabled);
	else return -1;
	apmib_get(MIB_OP_MODE,(void *)&opMode);
	if(opMode!=WISP_MODE)
		return -1;
	apmib_save_wlanIdx();
	
	sprintf(wlan_wanIfName,"wlan%d",wlanId);
	SetWlan_idx(wlan_wanIfName);
	//for wisp rpt mode,only care root ap
	apmib_get(MIB_WLAN_MODE, (void *)&wlanMode);
	if((AP_MODE==wlanMode || AP_MESH_MODE==wlanMode || MESH_MODE==wlanMode || AP_WDS_MODE==wlanMode ) && rptEnabled)
	{
		if(wlanId == 0)
			*pIface = "wlan0-vxd";
		else if(1 == wlanId)
			*pIface = "wlan1-vxd";
		else return -1;
	}else
	{
		char * ptmp = strstr(*pIface,"-vxd");
		if(ptmp)
			memset(ptmp,0,sizeof(char)*strlen("-vxd"));
	}
	apmib_recov_wlanIdx();
	return 0;
}

/////////////////////////////////////////////////////////////////////////////
int isConnectPPP()
{
	struct stat status;

	if ( stat("/etc/ppp/link", &status) < 0)
		return 0;

	return 1;
}


int getWanInfo(char *pWanIP, char *pWanMask, char *pWanDefIP, char *pWanHWAddr)
{
	DHCP_T dhcp;
	OPMODE_T opmode=-1;
	unsigned int wispWanId=0;
	char *iface=NULL;
	struct in_addr	intaddr;
	struct sockaddr hwaddr;
	unsigned char *pMacAddr;
	int isWanPhyLink = 0;	
	if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
		return -1;
  
  if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
		return -1;

	if( !apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId))
		return -1;
	
	if ( dhcp == PPPOE || dhcp == PPTP || dhcp == L2TP || dhcp == USB3G ) { /* # keith: add l2tp support. 20080515 */
#ifdef MULTI_PPPOE
	if(dhcp == PPPOE){
		extern char  ppp_iface[32];
		iface = ppp_iface;
	}
#else
	iface = "ppp0";
#endif
		
		if ( !isConnectPPP() )
			iface = NULL;
	}
	else if (opmode == WISP_MODE){
		if(0 == wispWanId)
			iface = "wlan0";
		else if(1 == wispWanId)
			iface = "wlan1";
#ifdef CONFIG_SMART_REPEATER
		if(getWispRptIface(&iface,wispWanId)<0)
					return -1;
#endif			
	}
	else
		iface = "eth1";
	
#if defined(CONFIG_4G_LTE_SUPPORT)
	if (lte_wan()) {
		iface = "usb0";
		isWanPhyLink = 1;
	} else
#endif /* #if defined(CONFIG_4G_LTE_SUPPORT) */

	if(opmode != WISP_MODE)
	{
		if(iface){
			if((isWanPhyLink = getWanLink("eth1")) < 0){
				sprintf(pWanIP,"%s","0.0.0.0");
			}
		}	
	}
	
	if ( iface && getInAddr(iface, IP_ADDR, (void *)&intaddr ) && ((isWanPhyLink >= 0)) )
		sprintf(pWanIP,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanIP,"%s","0.0.0.0");

	if ( iface && getInAddr(iface, SUBNET_MASK, (void *)&intaddr ) && ((isWanPhyLink >= 0) ))
		sprintf(pWanMask,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanMask,"%s","0.0.0.0");

	if ( iface && getDefaultRoute(iface, &intaddr) && ((isWanPhyLink >= 0) )) {			
			sprintf(pWanDefIP,"%s",inet_ntoa(intaddr));
	}	
	else {
			sprintf(pWanDefIP,"%s","0.0.0.0");	
	}
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
	if (dhcp == PPPOE)
	{
		if (getInAddr("eth1", IP_ADDR, (void *)&intaddr ) && ((isWanPhyLink >= 0)) ) {
			strcat(pWanIP, ", ");
			strcat(pWanIP, inet_ntoa(intaddr));
		}
		else
			strcat(pWanIP, ", 0.0.0.0");

		if (getInAddr("eth1", SUBNET_MASK, (void *)&intaddr ) && ((isWanPhyLink >= 0) )) {
			strcat(pWanMask, ", ");
			strcat(pWanMask, inet_ntoa(intaddr));
		}
		else
			strcat(pWanMask, ", 0.0.0.0");
		
		if (getDefaultRoute("eth1", &intaddr) && ((isWanPhyLink >= 0) )) {
			strcat(pWanDefIP, ", ");
			strcat(pWanDefIP, inet_ntoa(intaddr));
		}
		else
			strcat(pWanDefIP, ", 0.0.0.0");
	}
#endif

	//To get wan hw addr
	if(opmode == WISP_MODE) {
		if(0 == wispWanId)
			iface = "wlan0";
		else if(1 == wispWanId)
			iface = "wlan1";
#ifdef CONFIG_SMART_REPEATER
		if(getWispRptIface(&iface,wispWanId)<0)
					return -1;
#endif			
	}	
	else
		iface = "eth1";
	
#if defined(CONFIG_4G_LTE_SUPPORT)
	if (lte_wan()) {
		iface = "usb0";
	}
#endif /* #if defined(CONFIG_4G_LTE_SUPPORT) */

	if ( getInAddr(iface, HW_ADDR, (void *)&hwaddr ) ) 
	{
		pMacAddr = (unsigned char *)hwaddr.sa_data;
		sprintf(pWanHWAddr,"%02x:%02x:%02x:%02x:%02x:%02x",pMacAddr[0], pMacAddr[1],pMacAddr[2], pMacAddr[3], pMacAddr[4], pMacAddr[5]);
	}
	else
		sprintf(pWanHWAddr,"%s","00:00:00:00:00:00");

	return 0;
}



/*
*	return:
*	-1, error
*	0: get mac's name sucess
*	1: cannot find mac's name,return default name
*/
static int getChildMeshName(char *p_buffer, char *p_mac)
{
	int i = 0;
	char value[512] = {0};
	char MAC[32] = {0};
	char *p1 = NULL;
	char *p2 = NULL;
	char v_mac[32] = {0};
	char v_name[64] = {0};
	char addr[32] = {0};
	bss_info bss;

	if (p_mac == NULL || strlen(p_mac) == 0)
	{
		return -1;
	}
	sprintf(MAC, "%s", p_mac);
	getWlBssInfo("wlan0", &bss);
	sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", bss.bssid[0], bss.bssid[1],
				bss.bssid[2], bss.bssid[3], bss.bssid[4], bss.bssid[5]);	
	
	/* get main mesh's device name */
	if ( !strcasecmp(p_mac, addr) )
	{
		apmib_get(MIB_MAP_DEVICE_NAME, (void *)value);
		sprintf(p_buffer, "%s", value);
		return 0;
	}


	for (i=0; i < 16; i++)
	{
		apmib_get(MIB_KLINK_SLAVE1_MESH_NAME+i, (void *)value);
		//printf("[get_child_mesh_name] flash get MIB_KLINK_SLAVE1_MESH_NAME+%d value = %s\n", i,value);

		if (!strlen(value))
			continue;
		
		to_upper(MAC);
		p1 = strstr(value, p_mac);
		p2 = strstr(value, MAC);
		
		if ( (NULL != p1) )
		{
			sscanf(value, "%[^;];%[^;]", v_mac, v_name);	
			//printf("p1 v_mac = %s name = %s\n", v_mac, v_name);
			sprintf(p_buffer, "%s", v_name);
			return 0;
		}
		else if (NULL != p2)
		{
			sscanf(value, "%[^;];%[^;]", v_mac, v_name);
			//printf("p2 v_mac = %s name = %s\n", v_mac, v_name);
			sprintf(p_buffer, "%s", v_name);
			return 0;
		}
	}
	
	return 1;
}
/* 022311667782 to 02:23:11:66:77:82 */
int formatMacToStr(char *p_in, char *buffer)
{
	int i;
	int step = 0;
	memset(buffer, 0, sizeof(buffer));


	//printf("in mac buffer = %s\n", p_str);
	if (strlen(p_in)!= 12)
		return -1;

	for(i=0; i<5; i++)
	{
		strncat(buffer, p_in+step, 2);
		strcat(buffer, ":");
		step+=2;
	}

	strncat(buffer, p_in + step, 2);
	//printf("out of mac buffer = %s\n", buffer);
	return 0;
}
extern unsigned char *fwVersion;

void addExtStationInfoToTopology(cJSON * obj, RTK_LAN_DEVICE_INFO_T *devinfo)
{
    cJSON *head;
    cJSON *pos;
	cJSON *nb;
    cJSON *station_mac;
    unsigned char mac[6];
    int idx;
    char buf[64];
	char dev_name[32] = {0};
	char tmp[32] = {0};
	char child_mac[32] = {0};
	char app_device_name[64] = {0};

    head = cJSON_GetObjectItem(obj, "mac_address");
    if(head != NULL)
    {
        if(string_to_hex(head->valuestring, mac, 12))
        {
            idx = getMacIdx(devinfo, mac, MAX_STA_NUM);
            if(idx < MAX_STA_NUM)
            {
                devinfo[idx].slave_flg = 1;    //mark mesh slave device
            }
        }
    }

	strncpy(buf, fwVersion, sizeof(buf));
	getSlaveVersion(buf, head->valuestring, 0);
	cJSON_InsertStringToObject(obj, 3, "device_version", buf);

	
	//printf("topology.c .....\n");
#if 1
	formatMacToStr(tmp, child_mac);
	if (getChildMeshName(app_device_name, child_mac) == 0)
		cJSON_ReplaceItemInObject(obj, "device_name" , cJSON_CreateString(app_device_name));
	head = cJSON_GetObjectItem(obj, "neighbor_devices");
	if(head != NULL)
	{

		for(pos = head->child; pos != NULL; pos = pos->next)
		{
			nb = cJSON_GetObjectItem(pos, "neighbor_mac");
			if(nb != NULL)
			{
				sprintf(tmp, "%s", nb->valuestring);
				formatMacToStr(tmp, child_mac);
				if (getChildMeshName(app_device_name, child_mac) == 0)
				{
					cJSON_ReplaceItemInObject(pos, "neighbor_name" , cJSON_CreateString(app_device_name));
				}
			}
		}
	}
	else
	{
	printf("[%s:%d] can't find neighbor_devices.", __FUNCTION__, __LINE__);
	}

	head = cJSON_GetObjectItem(obj, "child_devices");
	if(head != NULL)
	{

		for(pos = head->child; pos != NULL; pos = pos->next)
		{
			nb = cJSON_GetObjectItem(pos, "mac_address");
			if(nb != NULL)
			{
				sprintf(tmp, "%s", nb->valuestring);
				formatMacToStr(tmp, child_mac);
				if (getChildMeshName(app_device_name, child_mac) == 0)
				{
					cJSON_ReplaceItemInObject(pos, "device_name" , cJSON_CreateString(app_device_name));
				}
			}
		}
	}
	else
	{
	printf("[%s:%d] can't find child_devices.", __FUNCTION__, __LINE__);
	}
#endif	
    head = cJSON_GetObjectItem(obj, "station_info");
    if(head != NULL)
    {
        for(pos = head->child; pos != NULL; pos = pos->next)
        {
            station_mac = cJSON_GetObjectItem(pos, "station_mac");
            if(station_mac != NULL)
            {
                if(string_to_hex(station_mac->valuestring, mac, 12))
                {
                    idx = getMacIdx(devinfo, mac, MAX_STA_NUM);
                    if(idx < MAX_STA_NUM)
                    {
                        strcpy(buf, inet_ntoa((*((struct in_addr *)&(devinfo[idx].ip)))));
                        cJSON_AddStringToObject(pos, "station_ip", buf);
                        cJSON_AddStringToObject(pos, "station_hostname", devinfo[idx].hostname);
                        cJSON_AddStringToObject(pos, "station_brand", devinfo[idx].brand);
                        cJSON_AddStringToObject(pos, "station_link_time", "null");

                        devinfo[idx].slave_flg = 1;
                    }
                }
            }
        }
    }
    else
    {
        printf("[%s:%d] can't find station_info.", __FUNCTION__, __LINE__);
    }

    head = cJSON_GetObjectItem(obj, "child_devices");

    if(head != NULL)
    {
        for(pos = head->child; pos != NULL; pos = pos->next)
        {
            addExtStationInfoToTopology(pos, devinfo);
        }
    }
    else
    {
        printf("[%s:%d] can't find child_devices.", __FUNCTION__, __LINE__);
    }

    return;
}

/*
{
       "device_name":"EasyMesh_Device_host",
       "ip_addr":"192.168.1.211",
       "mac_address":"cc2d2110f0dc",
       "neighbor_devices":[
           {
               "neighbor_mac":"00e046614455",
               "neighbor_name":"EasyMesh_Device2",
               "neighbor_rssi":"43",
               "neighbor_band":"TBU"
           }
       ],
       "station_info":[
           {
               "station_mac":"40331a573909",
               "station_rssi":"61",
               "station_connected_band":"5G",
               "station_downlink":"150",
               "station_uplink":"108"
               "station_ip":"192.168.1.10"
               "station_hostname":"mate20"
               "station_brand":"HUAWEI"
               "station_link_time":"68"
           }
       ],
       "child_devices":[
           Object{...},
           Object{...}
       ]
   }
*/

cJSON *getMeshTopologyJSON()
{
    FILE *fp;
    cJSON *root;
    char buf[512];
    RTK_LAN_DEVICE_INFO_T devinfo[MAX_STA_NUM] = {0};
    int num = 0;
    cJSON *obj_station;
    int i;

    rtk_get_lan_device_info(&num, devinfo, MAX_STA_NUM);
    fp = fopen("/tmp/topology_json", "r");
	if (fp == NULL) 
    {
        struct in_addr	intaddr;
        struct sockaddr hwaddr;
        unsigned char *mac;
        
		root = cJSON_CreateObject();
        if(root == NULL)
        {
            //printf("[%s:%d] cJSON_CreateObject fail.", __FUNCTION__, __LINE__);
            return NULL;
        }
        if (!apmib_get( MIB_MAP_DEVICE_NAME, (void *)buf)) 
        {
			sprintf(buf, "%s", "null" );
		}
        cJSON_AddStringToObject(root, "device_name", buf);

        getInAddr("br0", IP_ADDR, (void *)&intaddr );
        sprintf(buf, "%s", inet_ntoa(intaddr) );
        cJSON_AddStringToObject(root, "ip_addr", buf);

        mac = (unsigned char *)hwaddr.sa_data;
		sprintf(buf,"%02x%02x%02x%02x%02x%02x",mac[0], mac[1],mac[2], mac[3], mac[4], mac[5]);
        cJSON_AddStringToObject(root, "mac_address", buf);
        cJSON_AddStringToObject(root, "device_version", fwVersion);
        cJSON_AddItemToObject(root, "neighbor_devices", cJSON_CreateArray());

        cJSON *obj_array;
        cJSON_AddItemToObject(root, "station_info", obj_array = cJSON_CreateArray());
        if(obj_array != NULL)
        {
            for(i = 0; i < num; i++)
            {
                if(devinfo[i].on_link == 1)
                {
                    obj_station = creatJSONMeshStationOBJ(&devinfo[i]);
                    cJSON_AddItemToArray(obj_array, obj_station);
                }
            }
        }
        
        cJSON_AddItemToObject(root, "child_devices", cJSON_CreateArray());
       
	}
    else
    {
	ssize_t read;
	size_t  len   = 0;
	char*	line  = NULL;
	read = getline(&line, &len, fp);
	fclose(fp);
        if(line == NULL)
        {
            printf("[%s:%d] getline fail.", __FUNCTION__, __LINE__);
            return NULL;
        }

        root = cJSON_Parse(line);
        free(line);

        if(root == NULL)
        {
            //printf("[%s:%d] cJSON_Parse fail.", __FUNCTION__, __LINE__);
            return NULL;
        }

        addExtStationInfoToTopology(root, devinfo);
        cJSON *obj;
        obj = cJSON_GetObjectItem(root, "station_info");
        if(obj != NULL)
        {
            for(i = 0; i < num; i++)
            {
                if(devinfo[i].on_link == 1 && devinfo[i].slave_flg == 0)
                {
                    obj_station = creatJSONMeshStationOBJ(&devinfo[i]);
                    cJSON_AddItemToArray(obj, obj_station);
                }
            }
        }

    }

    return root;
}

void CalcOnlineClientNum(cJSON *obj, int *num)
{
    cJSON *station_array;
    cJSON *head;
    cJSON *pos;

    station_array = cJSON_GetObjectItem(obj, "station_info");
    *num += cJSON_GetArraySize(station_array);

    head = cJSON_GetObjectItem(obj, "child_devices");

    if(head != NULL)
    {
        for(pos = head->child; pos != NULL; pos = pos->next)
        {
            CalcOnlineClientNum(pos, num);
        }
    }
    else
    {
        //printf("[%s:%d] can't find child_devices.", __FUNCTION__, __LINE__);
    }

    return;
}

#define	TIMER_CONTINUE	0
#define	TIMER_REMOVE	1

#define WEB_TOPOLOGY_TXT "/tmp/web_topology.txt"

#define WEB_TOPOLOGY_SIZE 10240


int meshTopology()
{  
    cJSON *root;
    char *out;
	char cmd[WEB_TOPOLOGY_SIZE] = {0};

    root = getMeshTopologyJSON();
    if(root == NULL)
    {
        printf("[%s:%d] getMeshTopologyJSON fail.", __FUNCTION__, __LINE__);
        return -1;
    }
    out = cJSON_Print(root);
	cJSON_Delete(root);	
    if(out == NULL)
    {
        printf("[%s:%d] cJSON out fail.", __FUNCTION__, __LINE__);
        return -1;
    }

	//printf("topology out = {%s}\n", out);
	sprintf(cmd, "rm %s -rf", WEB_TOPOLOGY_TXT);
	system(cmd);

	int len = 0;
	len = strlen(out);

	int fd = open(WEB_TOPOLOGY_TXT, O_RDWR|O_CREAT);
	write(fd, out, len);

	close(fd);
	free(out);
	return TIMER_CONTINUE;
}


