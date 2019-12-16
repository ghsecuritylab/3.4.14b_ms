/* options.h */
#ifndef _OPTIONS_H
#define _OPTIONS_H

#include "packet.h"

#define TYPE_MASK	0x0F

/*haopeng 2019-12-10:add kingsignal dhcp125 option r*/
#define DHCP_KINGSIGNAL_OPTS	                             0x7D
#define VENDOR_KINGSIGNAL_SUBOPTIONS		300252   /*  can not find kingsignal enterprise suboptions in (IANA),here use stock code*/
#define DEVICE_OUI_CODE                                          1
#define DEVICE_SERIAL_NUMBER_CODE               2
#define DEVICE_PRODUCT_CLASS_CODE               3
#define VENDOR_BUFSIZE          			          64
#define  OPTION_LEN                                                     4
/*haopeng 2019-12-10:add end*/


enum {
	OPTION_IP=1,
	OPTION_IP_PAIR,
	OPTION_STRING,
	OPTION_BOOLEAN,
	OPTION_U8,
	OPTION_U16,
	OPTION_S16,
	OPTION_U32,
	OPTION_S32
};

#define OPTION_REQ	0x10 /* have the client request this option */
#define OPTION_LIST	0x20 /* There can be a list of 1 or more of these */

struct dhcp_option {
	char name[10];
	char flags;
	unsigned char code;
};

extern struct dhcp_option options[];
extern int option_lengths[];

unsigned char *get_option(struct dhcpMessage *packet, int code);
int end_option(unsigned char *optionptr);
int add_option_string(unsigned char *optionptr, unsigned char *string);
int add_simple_option(unsigned char *optionptr, unsigned char code, u_int32_t data);
struct option_set *find_option(struct option_set *opt_list, char code);
void attach_option(struct option_set **opt_list, struct dhcp_option *option, char *buffer, int length);

#endif
