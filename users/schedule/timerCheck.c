
/*
Copyright (c) 2019, All rights reserved.

File         : timeCheck.c
Status       : Current
Description  : 

Author       : lhw
Contact      : xxhanwen@163.com

Revision     : 2019-09 
Description  : Primary released

## Please log your description here for your modication ##

Revision     : 
Modifier     : 
Description  : 

*/

/* Standard headers */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>		/* gethostbyname, getnetbyname */
#include <net/ethernet.h>	/* struct ether_addr */
#include <sys/time.h>		/* struct timeval */
#include <unistd.h>

#include "apmib.h"
#include "trace.h"
#include <linux/wireless.h>
#include <dirent.h>

#define READ_BUF_SIZE	50

#define SSID_LEN 32

typedef enum _wlan_mac_state {
    STATE_DISABLED=0, STATE_IDLE, STATE_SCANNING, STATE_STARTED, STATE_CONNECTED, STATE_WAITFORKEY
} wlan_mac_state;

typedef struct _bss_info {
    unsigned char state;
    unsigned char channel;
    unsigned char txRate;
    unsigned char bssid[6];
    unsigned char rssi, sq;	// RSSI  and signal strength
    unsigned char ssid[SSID_LEN+1];
} bss_info;

static int agent_offline_time_cnt = 0;    //agent offline time
static int agent_restart_cnt = 0;         //kill and restart map_agent cnt
static int no_map_agent_time_cnt = 0;
static int no_map_controller_time_cnt = 0;


extern pid_t find_pid_by_name( char* pidName)
{
	DIR *dir;
	struct dirent *next;

	pid_t pid;

	if ( strcmp(pidName, "init")==0)
		return 1;

	dir = opendir("/proc");
	if (!dir) {
		printf("Cannot open /proc");
		return 0;
	}

	while ((next = readdir(dir)) != NULL) {
		FILE *status;
		char filename[READ_BUF_SIZE];
		char buffer[READ_BUF_SIZE];
		char name[READ_BUF_SIZE];

		/* Must skip ".." since that is outside /proc */
		if (strcmp(next->d_name, "..") == 0)
			continue;

		/* If it isn't a number, we don't want it */
		if (!isdigit(*next->d_name))
			continue;

		sprintf(filename, "/proc/%s/status", next->d_name);
		if (! (status = fopen(filename, "r")) ) {
			continue;
		}
		if (fgets(buffer, READ_BUF_SIZE-1, status) == NULL) {
			fclose(status);
			continue;
		}
		fclose(status);

		/* Buffer should contain a string like "Name:   binary_name" */
		sscanf(buffer, "%*s %s", name);
		if (strcmp(name, pidName) == 0) {
		//	pidList=xrealloc( pidList, sizeof(pid_t) * (i+2));
			pid=(pid_t)strtol(next->d_name, NULL, 0);
			closedir(dir);
			return pid;
		}
	}	
	closedir(dir);
	return 0;
}

void AgentDhcpdCheck()
{
    //if agent never joined mesh,open dhcpd, otherwise close
    int map_configured_band;
    int map_state;
    int lan_dhcp_mode;
    int first_login;
    
    apmib_get(MIB_MAP_CONFIGURED_BAND,(void *)&map_configured_band);
    apmib_get(MIB_MAP_CONTROLLER, (void *)&map_state);
    apmib_get(MIB_DHCP,(void *)&lan_dhcp_mode);
    apmib_get(MIB_FIRST_LOGIN, (void *)&first_login);
    
    if(lan_dhcp_mode == DHCP_CLIENT && map_state == 2)
    {
        //printf("[%s:%d] map_configured_band = %d\n", __FUNCTION__, __LINE__, map_configured_band);
        if(first_login == 1 || map_configured_band == 3)
        {					
			if (find_pid_by_name("udhcpd") > 0)
			{
                DPrintf("find and kill udhcpd.\n");
				system("killall -9 udhcpd >/dev/null 2>&1");
                system("rm -f /var/run/udhcpd.pid >/dev/null 2>&1");
			}	
        }
    }
}

void AgentWlanStaCheck()
{
    char cmd_buf[100];
    FILE *fd;
    int map_configured_band;
    int map_state;
    char *ptr;
    FILE *fp_wps_sta;
    int wps_sta_value;
    int first_login;
    
    apmib_get(MIB_MAP_CONFIGURED_BAND,(void *)&map_configured_band);
    apmib_get(MIB_MAP_CONTROLLER, (void *)&map_state);
    apmib_get(MIB_FIRST_LOGIN, (void *)&first_login);
    fp_wps_sta = fopen("/tmp/wscd_status", "r");
    if(fp_wps_sta== NULL)
    {
        DPrintf("open /tmp/wscd_status fail.\n");
		return;
    }
 
    memset(cmd_buf, 0, sizeof(cmd_buf));
    if(fgets(cmd_buf, sizeof(cmd_buf), fp_wps_sta))
    {
        wps_sta_value = atoi(cmd_buf);  
    }
    else
    {
        DPrintf("read /tmp/wscd_status fail.\n");
        fclose(fp_wps_sta);
        return;
    }
    fclose(fp_wps_sta);

    if(map_state == 2 
        && (first_login != 1 && map_configured_band != 3)
        && wps_sta_value != 0)
    {
        sprintf(cmd_buf, "iwpriv wlan0 get_mib func_off > /tmp/func_off");
        system(cmd_buf);
        fd = fopen("/tmp/func_off", "r");
        if(fd == NULL)
        {
            DPrintf("read func_off error.\n");
    		return;
        }
        memset(cmd_buf, 0, sizeof(cmd_buf));
        if(fgets(cmd_buf, sizeof(cmd_buf), fd))
        {
            ptr = strstr(cmd_buf, "get_mib:");
            if(ptr)
            {
                if(*(ptr+8) == '1')
                {
                    DTRACE(DTRACE_TIMER_CHECK, "set wlan0 func_off to 0.\n");
                    sprintf(cmd_buf, "iwpriv wlan0 set_mib func_off=0");
                    system(cmd_buf);
                }
            }
        }

        fclose(fd);
        
        sprintf(cmd_buf, "iwpriv wlan1 get_mib func_off > /tmp/func_off");
        system(cmd_buf);
        fd = fopen("/tmp/func_off", "r");
        if(fd == NULL)
        {
            DPrintf("read func_off error.\n");
    		return;
        }
        memset(cmd_buf, 0, sizeof(cmd_buf));
        if(fgets(cmd_buf, sizeof(cmd_buf), fd))
        {
            ptr = strstr(cmd_buf, "get_mib:");
            if(ptr)
            {
                if(*(ptr+8) == '1')
                {
                    DTRACE(DTRACE_TIMER_CHECK, "set wlan1 func_off to 0.\n");
                    sprintf(cmd_buf, "iwpriv wlan1 set_mib func_off=0");
                    system(cmd_buf);
                }
            }
        }
        
        fclose(fd);
    }

}

#define RTL8651_IOCTL_GETWANLINKSTATUS 2000
static int re865xIoctl(char *name, unsigned int arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3)
{
    unsigned int args[4];
    struct ifreq ifr;
    int sockfd;
    unsigned int *p=arg3;
    args[0] = arg0;
    args[1] = arg1;
    args[2] = arg2;
    args[3] = arg3;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      perror("fatal error socket\n");
      return -3;
    }

    strcpy((char*)&ifr.ifr_name, name);
    ((unsigned int *)(&ifr.ifr_data))[0] = (unsigned int)args;

    if (ioctl(sockfd, SIOCDEVPRIVATE, &ifr)<0)
    {
      perror("device ioctl:");
      close(sockfd);
      return -1;
    }
    close(sockfd);
    return 0;
}

int getWanLink(char *interface)
{
	int    ret=-1;
	int    args[0];

	re865xIoctl(interface, RTL8651_IOCTL_GETWANLINKSTATUS, (unsigned int)(args), 0, (unsigned int)&ret) ;
	return ret;
}

static inline int iw_get_ext(int skfd, char *ifname, int request, struct iwreq *pwrq)
{
	/* Set device name */
	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
	/* Do the request */
	return(ioctl(skfd, request, pwrq));
}

int getWlBssInfo(char *interface, bss_info *pInfo)
{
#ifndef NO_ACTION
    int skfd=0;
    struct iwreq wrq;



    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
      /* If no wireless name : no wireless extensions */
      {
         DPrintf("get wireless name fail.\n");
      	 close( skfd );
        return -1;
      }

    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = sizeof(bss_info);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSINFO, &wrq) < 0)
    {
        DPrintf("get bssinfo fail.\n");
    	close( skfd );
	    return -1;
	}
    close( skfd );
#else
    memset(pInfo, 0, sizeof(bss_info)); 
#endif

    return 0;
}

void SetStaLed(int color, int mode)
{
    char buf[100];

    sprintf(buf, "echo %d > /proc/gpio_color", color);
    system(buf);
    
    sprintf(buf, "echo %d > /proc/gpio_mode", mode);
    system(buf);
}
void DoStaLedControl()
{
    char buf[100];
    FILE *fp_led_color;
    FILE *fp_led_mode;
    FILE *fp_wps_sta;
    FILE *fp_net_flag;
    int map_configured_band;
    int map_state;
    int first_login;
    int led_color_value;
    int led_mode_value;
    int wps_sta_value;
    bss_info bss;
    int led_enable;
    int led_ctrl_disable;
    int net_flag = 0;

    apmib_get(MIB_MAP_CONFIGURED_BAND,(void *)&map_configured_band);
    apmib_get(MIB_MAP_CONTROLLER, (void *)&map_state);
    apmib_get(MIB_FIRST_LOGIN, (void *)&first_login);
    apmib_get(MIB_LED_ENABLE, (void *)&led_enable);  
    apmib_get(MIB_LED_CONTROL_DISABLE, (void *)&led_ctrl_disable);

     if(first_login != 1 && map_state == 2)
     {       
        if(map_configured_band == 3)
        {
            first_login = 1;
            if(!apmib_set(MIB_FIRST_LOGIN, (void *)&first_login))
            {
        		DPrintf("set MIB_FIRST_LOGIN fail.\n");
    	    }
            else
            {
                if(apmib_update(CURRENT_SETTING) <= 0)
                {
                    DPrintf("apmib_update CURRENT_SETTING fail.\n");
                }
            }
        }
     }

    fp_led_color = fopen("/proc/gpio_color", "r+");
    if(fp_led_color == NULL)
    {
        DPrintf("open /proc/gpio_color fail.\n");
		return;
    }
    fp_led_mode = fopen("/proc/gpio_mode", "r+");
    if(fp_led_mode == NULL)
    {
        DPrintf("open /proc/gpio_mode fail.\n");
		return;
    }
    fp_wps_sta = fopen("/tmp/wscd_status", "r");
    if(fp_wps_sta== NULL)
    {
        DPrintf("open /tmp/wscd_status fail.\n");
		return;
    }
    
    memset(buf, 0, sizeof(buf));
    if(fgets(buf, sizeof(buf), fp_led_color))
    {
        led_color_value = atoi(buf);  
    }
    else
    {
        DPrintf("read /proc/gpio_color fail.\n");
        goto ERR_RET;
    }
    memset(buf, 0, sizeof(buf));
    if(fgets(buf, sizeof(buf), fp_led_mode))
    {
        led_mode_value = atoi(buf);  
    }
    else
    {
        DPrintf("read /proc/gpio_mode fail.\n");
        goto ERR_RET;
    }
    memset(buf, 0, sizeof(buf));
    if(fgets(buf, sizeof(buf), fp_wps_sta))
    {
        wps_sta_value = atoi(buf);  
    }
    else
    {
        DPrintf("read /tmp/wscd_status fail.\n");
        goto ERR_RET;
    }

    if(map_state == 2)
    {
        fp_net_flag = fopen("/tmp/netFlag", "r");
        if(fp_net_flag== NULL)
        {
            net_flag = 0;
        }
        else
        {
            memset(buf, 0, sizeof(buf));
            if(fgets(buf, sizeof(buf), fp_net_flag))
            {
                net_flag = atoi(buf);  
            }
            else
            {
                net_flag = 0;
            }
            fclose(fp_net_flag);
        }
    }
    else
    {
        net_flag = 0;
    }

    if(wps_sta_value != 0 && led_ctrl_disable != 1)
    {
       // DTRACE(DTRACE_TIMER_CHECK, "DoStaLedControl run.\n");
        if(led_enable == 0)
        {
            if(led_mode_value != 0)
            {
                DTRACE(DTRACE_TIMER_CHECK, "led OFF.\n");
                SetStaLed(0, 0);
            }
        }
        else
        {
            if(map_state == 2)
            {
                if(first_login != 1 && map_configured_band != 3)
                {
                    if(led_color_value != 0 || led_mode_value != 1)
                    {
                        DTRACE(DTRACE_TIMER_CHECK, "set led to red, not connect controller.\n");
                        SetStaLed(0, 1);    //red if not connect controller
                    }
                }
                else
                {
                    if ( getWlBssInfo("wlan0-vxd", &bss) >= 0)
                    {
                        DTRACE(DTRACE_TIMER_CHECK, "bss.state = %d, bss.rssi = %d.\n", bss.state, bss.rssi);
                        if(bss.state == STATE_SCANNING)
                        {
                            if(led_color_value != 2 || led_mode_value != 2)
                            {
                                DTRACE(DTRACE_TIMER_CHECK, "set led to blue blink, SCANNING.\n");
                                SetStaLed(2, 2);    //blue blink when SCANNIN
                            }
                        }
                        else if(bss.state == STATE_CONNECTED)
                        {
                            if(bss.rssi <= 20)
                            {
                                if(led_color_value != 1 || led_mode_value != 2)
                                {
                                    DTRACE(DTRACE_TIMER_CHECK, "set led to green blink, weak signal.\n");
                                    SetStaLed(1, 2);     //green blink when weak signal
                                }
                            }
                            else
                            {
                                if(led_color_value != 1 || led_mode_value != 1)
                                {
                                    DTRACE(DTRACE_TIMER_CHECK, "set led to green, connected to controller.\n");
                                    SetStaLed(1, 1);     //green if connected to controller
                                }
                            }
                        }
                        else
                        {
                            if(net_flag == 1)
                            {
                                if(led_color_value != 1 || led_mode_value != 1)
                                {
                                    DTRACE(DTRACE_TIMER_CHECK, "set led to green, connected to controller.\n");
                                    SetStaLed(1, 1);     //green if connected to controller
                                }
                            }
                            else
                            {
                                if(led_color_value != 2 || led_mode_value != 2)
                                {
                                    DTRACE(DTRACE_TIMER_CHECK, "set led to blue blink, when not SCANNING.\n");
                                    SetStaLed(2, 2);    //blue blink when SCANNIN
                                }
                            }
                        }
                    }
                    else
                    {
                         DPrintf("getWlBssInfo fail.\n");
                    }
                }
            }
            else if(map_state == 1)
            {
                if(first_login != 1)
                {
                    if(led_color_value != 0 || led_mode_value != 1)
                    {
                        DTRACE(DTRACE_TIMER_CHECK, "set led to red, not set first_login.\n");
                        SetStaLed(0, 1);    //red if not set first_login
                    }
                }
                else
                {
                        int ret = getWanLink("eth1");
                        if(ret < 0)
                        {
                            if(led_color_value != 2 || led_mode_value != 1)
                            {
                                DTRACE(DTRACE_TIMER_CHECK, "set led to blue, no internet.\n");
                                SetStaLed(2, 1);    //blue if no internet
                            }
                        }
                        else
                        {
                            if(led_color_value != 1 || led_mode_value != 1)
                            {
                                DTRACE(DTRACE_TIMER_CHECK, "set led to green, has internet.\n");
                                SetStaLed(1, 1);     //green if has internet
                            }
                        }
                }
            }
            else
            {
                if(led_color_value != 0 || led_mode_value != 1)
                {
                    DTRACE(DTRACE_TIMER_CHECK, "set led to red, not set mac, map_state = %d.\n", map_state);
                    SetStaLed(0, 1);;    //red if not set mac
                }
            }
        }
    }

ERR_RET:
    fclose(fp_led_color);
    fclose(fp_led_mode);
    fclose(fp_wps_sta);
}

int doMAPCheck()
{
    int map_state;
    int first_login;   
    bss_info bss;
    char tmp_buf[256];
    int map_configured_band;
    FILE *fp_net_flag;
    int net_flag = 0;
   
    apmib_get(MIB_MAP_CONTROLLER, (void *)&map_state);
    apmib_get(MIB_FIRST_LOGIN, (void *)&first_login);
    apmib_get(MIB_MAP_CONFIGURED_BAND,(void *)&map_configured_band);

    if(map_state == 2)
    {
        fp_net_flag = fopen("/tmp/netFlag", "r");
        if(fp_net_flag== NULL)
        {
            net_flag = 0;
        }
        else
        {
            memset(tmp_buf, 0, sizeof(tmp_buf));
            if(fgets(tmp_buf, sizeof(tmp_buf), fp_net_flag))
            {
                net_flag = atoi(tmp_buf);  
            }
            else
            {
                net_flag = 0;
            }
            fclose(fp_net_flag);
        }
    }
    else
    {
        net_flag = 0;
    }

    if( (first_login == 1 || map_configured_band == 3)
        && map_state == 2)
    {
         if(getWlBssInfo("wlan0-vxd", &bss) >= 0)
          {
            if( (bss.state == STATE_CONNECTED || net_flag == 1)
                && map_configured_band == 3)
            {
                agent_offline_time_cnt = 0;
                agent_restart_cnt = 0;
            }
            else
            {
                agent_offline_time_cnt++;
                if( (agent_restart_cnt == 0 && agent_offline_time_cnt >= 40)
                    || (agent_restart_cnt == 1 && agent_offline_time_cnt >= 30)
                    || (agent_restart_cnt == 2 && agent_offline_time_cnt >= 60)
                    || (agent_restart_cnt == 3 && agent_offline_time_cnt >= 180)
                    || (agent_restart_cnt == 4 && agent_offline_time_cnt >= 360) )
                {
                    DPrintf("restart map_agent, agent_restart_cnt = %d, agent_offline_time_cnt = %d .\n", agent_restart_cnt, agent_offline_time_cnt);

                    if (find_pid_by_name("map_agent") > 0) 
                    {
                        system("killall -9 map_agent >/dev/null 2>&1");
						sleep(1);
                    }
                    
                    system(" map_agent -dvv > /dev/null");
					sleep(2);

                     
                    if(agent_restart_cnt == 1
                        || agent_restart_cnt == 2
                        || agent_restart_cnt == 3
                        || agent_restart_cnt == 4)
                    {
                        sprintf(tmp_buf, "init.sh gw all");
                        system(tmp_buf);
                    }
                        
                    agent_restart_cnt++;
                    agent_offline_time_cnt = 0;                   
                }
            }
          }

         if (find_pid_by_name("map_agent") <= 0) 
         {
            DTRACE(DTRACE_TIMER_CHECK, "map_agent not find, no_map_agent_time_cnt = %d.\n", no_map_agent_time_cnt);
            no_map_agent_time_cnt++;
            if(no_map_agent_time_cnt >= 60)
            {
                no_map_agent_time_cnt = 0;
                system(" map_agent -dvv > /dev/null");
            }
         }
         else
         {
            no_map_agent_time_cnt = 0;
         }
    }

    if(first_login == 1 && map_state == 1)
    {
         if (find_pid_by_name("map_controller") <= 0) 
         {
            DTRACE(DTRACE_TIMER_CHECK, "map_controller not find, no_map_controller_time_cnt = %d.\n", no_map_controller_time_cnt);
            no_map_controller_time_cnt++;
            if(no_map_controller_time_cnt >= 60)
            {
                no_map_controller_time_cnt = 0;
                system(" map_controller -dvv > /dev/null");
            }
         }
         else
         {
            no_map_controller_time_cnt = 0;
         }
    }

    return 0;
    
}

void InitTimerCheck()
{
    int mib_val;
    
    mib_val = 0;
	apmib_set(MIB_LED_CONTROL_DISABLE, (void *)&mib_val);

    agent_restart_cnt = 0;
    agent_offline_time_cnt = 0;
    no_map_agent_time_cnt = 0;
    no_map_controller_time_cnt = 0;
}
//call ever 1s
int timerCheck()
{
    AgentDhcpdCheck();
    AgentWlanStaCheck();
    DoStaLedControl();

    return 0;
}

