/* 
 * options.c -- DHCP server option packet tools 
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "dhcpd.h"
#include "files.h"
#include "options.h"
#include "leases.h"
#if defined(CONFIG_RTL865X_KLD)	
extern unsigned char update_lease_time1;
extern unsigned char update_option_dns;
#endif
/* supported options are easily added here */
struct dhcp_option options[] = {
	/* name[10]	flags					code */
	{"subnet",	OPTION_IP | OPTION_REQ,			0x01},
	{"timezone",	OPTION_S32,				0x02},
/* Aded 20080508 for option 33 */
#ifdef UDHCPC_STATIC_ROUTE
	{"fixroute",OPTION_IP | OPTION_REQ,			0x21},
#endif

/* Aded 20080508 for option 121 */
#if defined(RFC3442) || defined(_PRMT_X_TELEFONICA_ES_DHCPOPTION_) 
#if defined(UDHCPC_RFC_CLASSLESS_STATIC_ROUTE) || defined(_PRMT_X_TELEFONICA_ES_DHCPOPTION_)
	{"rfc3442",OPTION_IP | OPTION_REQ,			0x79},
#endif
/* ----------------------------------- */
/* Aded 20080508 for option 249 */
#ifdef UDHCPC_MS_CLASSLESS_STATIC_ROUTE
	{"rfc3442",OPTION_IP | OPTION_REQ,			0xF9},
#endif
#endif
/* ----------------------------------- */
	{"router",	OPTION_IP | OPTION_LIST | OPTION_REQ,	0x03},
	{"timesvr",	OPTION_IP | OPTION_LIST,		0x04},
	{"namesvr",	OPTION_IP | OPTION_LIST,		0x05},
	{"dns",		OPTION_IP | OPTION_LIST | OPTION_REQ,	0x06},
	{"logsvr",	OPTION_IP | OPTION_LIST,		0x07},
	{"cookiesvr",	OPTION_IP | OPTION_LIST,		0x08},
	{"lprsvr",	OPTION_IP | OPTION_LIST,		0x09},
	{"hostname",	OPTION_STRING | OPTION_REQ,		0x0c},
	{"bootsize",	OPTION_U16,				0x0d},
	{"domain",	OPTION_STRING | OPTION_REQ,		0x0f},
	{"swapsvr",	OPTION_IP,				0x10},
	{"rootpath",	OPTION_STRING,				0x11},
	{"ipttl",	OPTION_U8,				0x17},
	{"mtu",		OPTION_U16,				0x1a},
	{"broadcast",	OPTION_IP | OPTION_REQ,			0x1c},
	{"ntpsrv",	OPTION_IP | OPTION_LIST,		0x2a},
#if defined(_PRMT_X_TELEFONICA_ES_DHCPOPTION_)
	{"vspecinfo",	OPTION_STRING | OPTION_REQ,		0x2b},
#endif
#ifdef CONFIG_SIXRD_SUPPORT
	{"6rd",		OPTION_STRING | OPTION_REQ, 	0xd4},	
#endif
	{"wins",	OPTION_IP | OPTION_LIST|OPTION_REQ,		0x2c},
	{"nbntype",	OPTION_U8 | OPTION_LIST|OPTION_REQ,		0x2e},
	{"nbscope",	OPTION_STRING | OPTION_LIST|OPTION_REQ,		0x2f},
	
	{"requestip",	OPTION_IP,				0x32},
	{"lease",	OPTION_U32,				0x33},
	{"dhcptype",	OPTION_U8,				0x35},
	{"serverid",	OPTION_IP,				0x36},
	{"message",	OPTION_STRING,				0x38},
	{"tftp",	OPTION_STRING,				0x42},
	{"bootfile",	OPTION_STRING,				0x43},
	{"",		0x00,				0x00}
};

/* Lengths of the different option types */
int option_lengths[] = {
	[OPTION_IP] =		4,
	[OPTION_IP_PAIR] =	8,
	[OPTION_BOOLEAN] =	1,
	[OPTION_STRING] =	1,
	[OPTION_U8] =		1,
	[OPTION_U16] =		2,
	[OPTION_S16] =		2,
	[OPTION_U32] =		4,
	[OPTION_S32] =		4
};


/* get an option with bounds checking (warning, not aligned). */
unsigned char *get_option(struct dhcpMessage *packet, int code)
{
	int i, length;
	unsigned char *optionptr=NULL;
	int over = 0, done = 0, curr = OPTION_FIELD;
	
	optionptr = packet->options;
	i = 0;
	length = 308;
	while (!done) {
		if (i >= length) {
			LOG(LOG_WARNING, "bogus packet, option fields too long.");
			return NULL;
		}
		if (optionptr[i + OPT_CODE] == code) {
			if (i + 1 + optionptr[i + OPT_LEN] >= length) {
				LOG(LOG_WARNING, "bogus packet, option fields too long.");
				return NULL;
			}
			return optionptr + i + 2;
		}			
		switch (optionptr[i + OPT_CODE]) {
		case DHCP_PADDING:
			i++;
			break;
		case DHCP_OPTION_OVER:
			if (i + 1 + optionptr[i + OPT_LEN] >= length) {
				LOG(LOG_WARNING, "bogus packet, option fields too long.");
				return NULL;
			}
			over = optionptr[i + 3];
			i += optionptr[OPT_LEN] + 2;
			break;
		case DHCP_END:
			if (curr == OPTION_FIELD && over & FILE_FIELD) {
				optionptr = packet->file;
				i = 0;
				length = 128;
				curr = FILE_FIELD;
			} else if (curr == FILE_FIELD && over & SNAME_FIELD) {
				optionptr = packet->sname;
				i = 0;
				length = 64;
				curr = SNAME_FIELD;
			} else done = 1;
			break;
		default:
			i += optionptr[OPT_LEN + i] + 2;
		}
	}
	return NULL;
}


/* return the position of the 'end' option (no bounds checking) */
int end_option(unsigned char *optionptr) 
{
	int i = 0;
	
	while (optionptr[i] != DHCP_END) {
		if (optionptr[i] == DHCP_PADDING) i++;
		else i += optionptr[i + OPT_LEN] + 2;
	}
	return i;
}


/* add an option string to the options (an option string contains an option code,
 * length, then data) */
int add_option_string(unsigned char *optionptr, unsigned char *string)
{
	int end = end_option(optionptr);
	
	/* end position + string length + option code/length + end option */
	if (end + string[OPT_LEN] + 2 + 1 >= 308) {
		LOG(LOG_ERR, "Option 0x%02x did not fit into the packet!", string[OPT_CODE]);
		return 0;
	}
	DEBUG(LOG_INFO, "adding option 0x%02x", string[OPT_CODE]);
	memcpy(optionptr + end, string, string[OPT_LEN] + 2);
	optionptr[end + string[OPT_LEN] + 2] = DHCP_END;
	return string[OPT_LEN] + 2;
}


/* add a one to four byte option to a packet */
int add_simple_option(unsigned char *optionptr, unsigned char code, u_int32_t data)
{
	char length = 0;
	int i;
	unsigned char option[2 + 4];
	unsigned char *u8;
	u_int16_t *u16;
	u_int32_t *u32;
	u_int32_t aligned;
	u8 = (unsigned char *) &aligned;
	u16 = (u_int16_t *) &aligned;
	u32 = &aligned;

	for (i = 0; options[i].code; i++)
		if (options[i].code == code) {
			length = option_lengths[options[i].flags & TYPE_MASK];
		}
		
	if (!length) {
		DEBUG(LOG_ERR, "Could not add option 0x%02x", code);
		return 0;
	}
	
	option[OPT_CODE] = code;
	option[OPT_LEN] = length;

	switch (length) {
		case 1: *u8 =  data; break;
		case 2: *u16 = data; break;
		case 4: *u32 = data; break;
	}
	memcpy(option + 2, &aligned, length);
	return add_option_string(optionptr, option);
}


/* find option 'code' in opt_list */
struct option_set *find_option(struct option_set *opt_list, char code)
{
	while (opt_list && opt_list->data[OPT_CODE] < code)
		opt_list = opt_list->next;

	if (opt_list && opt_list->data[OPT_CODE] == code) return opt_list;
	else return NULL;
}


/* add an option to the opt_list */
void attach_option(struct option_set **opt_list, struct dhcp_option *option, char *buffer, int length)
{
	struct option_set *existing, *new, **curr;

	/* add it to an existing option */
	if ((existing = find_option(*opt_list, option->code))) {
		DEBUG(LOG_INFO, "Attaching option %s to existing member of list", option->name);
#if defined(CONFIG_RTL865X_KLD)
		if (option->flags & OPTION_LIST) {
				if(!strcmp(option->name, "dns")){
					if(server_config.upateConfig_isp_dns == 1){
						if(update_lease_time1 ==1){
									if (existing->data[OPT_LEN] + length <= 255) {
												//printf("the orig length=%d\n", existing->data[OPT_LEN] );
												if(update_option_dns==0){
														existing->data = realloc(existing->data, length + 2);
														memcpy(existing->data+2, buffer, length);
														existing->data[OPT_LEN] = length;
														update_option_dns++;
													}else{
														existing->data = realloc(existing->data, existing->data[OPT_LEN] + length + 2);
														memcpy(existing->data + existing->data[OPT_LEN] + 2, buffer, length);
														existing->data[OPT_LEN] += length;
													}
									} 
							}
							#if 0
							else{
								if (existing->data[OPT_LEN] + length <= 255) {
										existing->data = realloc(existing->data, existing->data[OPT_LEN] + length + 2);
										memcpy(existing->data + existing->data[OPT_LEN] + 2, buffer, length);
										existing->data[OPT_LEN] += length;
								} /* else, ignore the data, we could put this in a second option in the future */
							}
							#endif
						}else{
								if (existing->data[OPT_LEN] + length <= 255) {
										existing->data = realloc(existing->data, existing->data[OPT_LEN] + length + 2);
										memcpy(existing->data + existing->data[OPT_LEN] + 2, buffer, length);
										existing->data[OPT_LEN] += length;
								} /* else, ignore the data, we could put this in a second option in the future */
						}
					}else{
						if (existing->data[OPT_LEN] + length <= 255) {
										existing->data = realloc(existing->data, existing->data[OPT_LEN] + length + 2);
										memcpy(existing->data + existing->data[OPT_LEN] + 2, buffer, length);
										existing->data[OPT_LEN] += length;
								} /* else, ignore the data, we could put this in a second option in the future */
					}
		}/* else, ignore the new data */
#else	
		if (option->flags & OPTION_LIST) {
			if (existing->data[OPT_LEN] + length <= 255) {
				existing->data = realloc(existing->data, existing->data[OPT_LEN] + length + 2);
				memcpy(existing->data + existing->data[OPT_LEN] + 2, buffer, length);
				existing->data[OPT_LEN] += length;
			} /* else, ignore the data, we could put this in a second option in the future */
		} /* else, ignore the new data */
#endif		
#if defined(CONFIG_RTL8186_TR)			
		else{
			//we should update the new data from isp for options of ours, not cascade
			if(server_config.upateConfig_isp==1){
				if(!strcmp(option->name, "domain")){
					if (existing->data[OPT_LEN] + length <= 255) {
						//printf("the orig length=%d\n", existing->data[OPT_LEN] );
					existing->data = realloc(existing->data, length + 2);
					memcpy(existing->data+2, buffer, length);
					existing->data[OPT_LEN] = length;
				} 
				}
			}
		}
#endif		
	} else {
		DEBUG(LOG_INFO, "Attaching option %s to list", option->name);
		
		/* make a new option */
		new = xmalloc(sizeof(struct option_set));
		new->data = xmalloc(length + 2);
		new->data[OPT_CODE] = option->code;
		new->data[OPT_LEN] = length;
		memcpy(new->data + 2, buffer, length);
		
		curr = opt_list;
		while (*curr && (*curr)->data[OPT_CODE] < option->code)
			curr = &(*curr)->next;
			
		new->next = *curr;
		*curr = new;		
#if defined(CONFIG_RTL865X_KLD)		
		if(!strcmp(option->name, "dns")){
			if(server_config.upateConfig_isp_dns == 1){
						if(update_lease_time1 ==1){
							update_option_dns++;
						}
					}
				}
#endif
	}
}


/*haopeng 2019-12-10:add dhcp option to dhcp packets*/
static inline int str_len (const uint8_t *str) 
{
    int len = 0;
    while (*str ++ != '\0') len ++;
    return len;
}

static int add_vendor_specific_sub_option(uint8_t *sub_options, uint8_t sub_code, const uint8_t *sub_value)
{
    /* sub options: Code + Len + Data */
    int lindex = 0; 
    int lsize; 
    
    int sub_options_size;
    int sub_value_len;

    /* check 'sub_value' is a valid value */

    while (sub_options[lindex + OPT_CODE] != 0) {
        lsize = sub_options[lindex + OPT_LEN];
        lindex += (lsize + OPT_DATA);
    }

    sub_value_len = str_len(sub_value);
	
    /* check, is it overload */
    sub_options[lindex + OPT_CODE] = sub_code;
    sub_options[lindex + OPT_LEN]  = (uint8_t) sub_value_len;
    memcpy(sub_options + lindex + OPT_DATA, sub_value, sub_value_len);  

    sub_options_size = lindex + (sub_value_len + OPT_DATA);

    return sub_options_size;
}

int add_vendor_specific_option(uint8_t *optionptr,

        uint32_t vendor_enterprise_code,
        const uint8_t *device_manufacture_oui,
        const uint8_t *device_serial_number,
        const uint8_t *device_product_class)
{
    uint8_t  vendor_option[128] = {0};

    int vendor_option_len;
    int vendor_enterprise_code_len = 4; /* sizeof vendor enterprise code */

    int sub_options_size_index;
    int sub_options_size =  0;  
    uint8_t *sub_options;

    vendor_option[OPT_CODE] = DHCP_KINGSIGNAL_OPTS;
    *((uint32_t *)(vendor_option + OPT_DATA)) = htonl(vendor_enterprise_code);

    /* add vendor specific sub options */
    sub_options_size_index = OPT_DATA + vendor_enterprise_code_len;
    sub_options = vendor_option + (sub_options_size_index + 1);

    sub_options_size = add_vendor_specific_sub_option(sub_options, 1, device_manufacture_oui);
    sub_options_size = add_vendor_specific_sub_option(sub_options, 2, device_serial_number);
    sub_options_size = add_vendor_specific_sub_option(sub_options, 3, device_product_class);

	/* update vendor sub options length */
	vendor_option[sub_options_size_index] = (uint8_t)sub_options_size;

    /* update vendor option(125) length */
    vendor_option_len = vendor_enterprise_code_len + (1 + sub_options_size);
    vendor_option[OPT_LEN] = (uint8_t)vendor_option_len;

    return add_option_string(optionptr, vendor_option);
}

static const uint8_t * get_vendor_specific_sub_option (const uint8_t *sub_options, uint32_t sub_options_size, int code)
{
	const uint8_t *sub_value = NULL;
	
	uint32_t sub_value_size;
	uint8_t sub_value_code;
	char *strNull="null";

	while (sub_options_size > 0) {
		sub_value_code = sub_options[OPT_CODE];
		sub_value_size = sub_options[OPT_LEN];

         if((sub_value_code != 1)&&(sub_value_code != 2)&&(sub_value_code != 3))
        	{	
        	 sub_value= strNull;
	sub_options = strNull;
	sub_options_size = 4;
        	 return sub_value;
        	}
		

		if (sub_value_size + OPT_DATA > sub_options_size) {
			/* TODO, log error msg */
			break;
		}

		if (sub_value_code == code) {
			sub_value = sub_options+ OPT_DATA;
			break;
		}

		sub_options += (OPT_DATA + sub_value_size);
		sub_options_size -= (OPT_DATA + sub_value_size);
	}

	return sub_value;
}
  
int get_vendor_specific_option(struct dhcpMessage *packet, 
		int oui_code, uint8_t *device_manufacture_oui, uint32_t *device_manufacture_oui_size,
		int serial_number_code, uint8_t *device_serial_number, uint32_t *device_serial_number_size,
		int product_class_code, uint8_t *device_product_class, uint32_t *device_product_class_size)
{
	uint8_t *vendor_options = NULL;
	uint32_t vendor_options_size= 0;

	uint8_t *vendor_sub_total_options = NULL; 
	uint32_t vendor_sub_options_total_size = 0;  

	const uint8_t *vendor_sub_option = NULL;
	uint32_t vendor_sub_option_size = 0;
	const char *strNull="null";
	char *strTest =NULL;
	if ((vendor_options = get_option(packet, DHCP_KINGSIGNAL_OPTS)) == NULL) {
		/* TODO, log error msg */
		return -1;
	} 

	vendor_options_size = vendor_options[-1];
	vendor_sub_options_total_size = vendor_options[4];

	/* TODO, check (vendor_options_size ==  (vendor_sub_options_total_size + 4 + 1) */
	vendor_sub_total_options = vendor_options + 4 + 1;	/* sizeof vendor enterprise code + sub options len byte */
	

	/* 4.gateway_manufacture_oui */
	vendor_sub_option = get_vendor_specific_sub_option(vendor_sub_total_options, vendor_sub_options_total_size, oui_code);
          // printf("----%s:%d\n vendor_sub_option[%s]-----\n",__FUNCTION__,__LINE__,vendor_sub_option);
	vendor_sub_option_size = vendor_sub_option[-1];
	if(strTest=strstr(vendor_sub_option,"d05157"))
	{
	 if (*device_manufacture_oui_size > vendor_sub_option_size) {
		memcpy(device_manufacture_oui, vendor_sub_option, vendor_sub_option_size);
		device_manufacture_oui[vendor_sub_option_size] = '\0';
		*device_manufacture_oui_size = vendor_sub_option_size;
		// printf("----%s:%d\n device_manufacture_oui[%s]-----\n",__FUNCTION__,__LINE__,device_manufacture_oui);
	} else {
		/* TODO, log error msg */
		*device_manufacture_oui_size = 0;
		//printf(" manufacture_oui_size=%d,sub_option_size=%d,sub_option=%s\n",device_manufacture_oui_size,vendor_sub_option_size,vendor_sub_option);
	}

	/* 5. gateway_serial_number */
	vendor_sub_option = get_vendor_specific_sub_option(vendor_sub_total_options, vendor_sub_options_total_size, serial_number_code);
	vendor_sub_option_size = vendor_sub_option[-1];
	 // printf("----%s:%d\n vendor_sub_option[%s]-len[%d]----\n",__FUNCTION__,__LINE__,vendor_sub_option,vendor_sub_option_size);
	 if (*device_serial_number_size > vendor_sub_option_size) {
		memcpy(device_serial_number, vendor_sub_option, vendor_sub_option_size);
		device_serial_number[vendor_sub_option_size] = '\0';
		*device_serial_number_size = vendor_sub_option_size;
		// printf("----%s:%d\n device_serial_number[%s]-----\n",__FUNCTION__,__LINE__,device_serial_number);
	} else {
		/* TODO, log error msg */
		*device_serial_number_size = 0;
		//printf(" serial_number_size=%d,sub_option_size=%d,sub_option=%s\n",device_serial_number_size,vendor_sub_option_size,vendor_sub_option);
	}

	/* 6. gateway_product_class */
	vendor_sub_option = get_vendor_specific_sub_option(vendor_sub_total_options, vendor_sub_options_total_size, product_class_code);
	vendor_sub_option_size = vendor_sub_option[-1];
	//printf("----%s:%d\n vendor_sub_option[%s]-----\n",__FUNCTION__,__LINE__,vendor_sub_option);
        if (*device_product_class_size > vendor_sub_option_size)
	{
		memcpy(device_product_class, vendor_sub_option, vendor_sub_option_size);
		device_product_class[vendor_sub_option_size] = '\0';
		*device_product_class_size = vendor_sub_option_size;
		//printf("----%s:%d\n device_product_class[%s]-----\n",__FUNCTION__,__LINE__,device_product_class);
	} else
	{
		/* TODO, log error msg */
		device_product_class_size = 0;
		/*if illegally  fill with null */
		//printf(" product_class_size=%d,sub_option_size=%d,sub_option=%s\n",device_product_class_size,vendor_sub_option_size,vendor_sub_option);
	}
	}
	else
	{
	/*fill null to other vendor's 125 option*/
	          memset(device_manufacture_oui,0,strlen("kingsignal"));
	         memset(device_serial_number,0,strlen("d05157"));
	         memset(device_product_class,0,strlen("mesh"));
		memcpy(device_manufacture_oui, strNull, strlen(strNull));
		memcpy(device_serial_number, strNull, strlen(strNull));
		memcpy(device_product_class, strNull, strlen(strNull));
	}
     printf("=>%s:%d\n oui[%s]-serial[%s]-class[%s]=\n",__FUNCTION__,__LINE__,device_manufacture_oui,device_serial_number,device_product_class);
	return 0;  
}
/*haopeng 2019-12-10:add end*/

