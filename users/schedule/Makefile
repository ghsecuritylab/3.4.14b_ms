#compiler
CC = msdk-linux-gcc

ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../.config
else
include $(DIR_USERS)/.config
endif

COMMON_CFLAGS =

ifeq ($(CONFIG_APP_MULTI_AP),y)
COMMON_CFLAGS += -DRTK_MULTI_AP
COMMON_CFLAGS += -DUNIVERSAL_REPEATER
COMMON_CFLAGS += -DWIFI_SIMPLE_CONFIG
endif

#external lib
APMIB_DIR = ../boa/apmib
CFLAGS := -s -Wall -Os
LDFLAGS := -s -Wall
IFLAGS := -I. -I$(APMIB_DIR)

SCHEDULE_DIR=$(shell pwd)
TARGET=schedule
$(TARGET):timer.o thread.o task.o etherAddr.o guestWlan.o eventHandle.o timerCheck.o topology.o klinkMgmt.o ../boa/src/cJSON.o ../klink/klinkLinksListFunc.o ../boa/src/version.o
	$(CC) timer.o thread.o task.o etherAddr.o guestWlan.o eventHandle.o timerCheck.o topology.o klinkMgmt.o ../boa/src/cJSON.o ../klink/klinkLinksListFunc.o ../boa/src/version.o -lm  -lrt  $(LDFLAGS) -L$(APMIB_DIR) -lapmib -o $(TARGET)
eventHandle.o: eventHandle.c
	$(CC) -c eventHandle.c -o eventHandle.o $(IFLAGS) $(LDFLAGS) -L$(APMIB_DIR) -lapmib
timer.o:timer.c task.o thread.o 
	$(CC) -c timer.c -o timer.o
thread.o: thread.c
	$(CC) -c thread.c -o thread.o
task.o: task.c etherAddr.o
	$(CC) -c task.c -o task.o
etherAddr.o: etherAddr.c
	$(CC) -c etherAddr.c -o etherAddr.o
guestWlan.o: guestWlan.c
	$(CC) -c guestWlan.c $(IFLAGS) $(LDFLAGS) -L$(APMIB_DIR) -lapmib -o guestWlan.o
timerCheck.o: timerCheck.c
	$(CC) -c timerCheck.c $(IFLAGS) $(LDFLAGS) $(COMMON_CFLAGS) -L$(APMIB_DIR) -lapmib -o timerCheck.o
cJSON.o: cJSON.c
	$(CC) -c cJSON.c $(IFLAGS) $(LDFLAGS) $(COMMON_CFLAGS) -lm -L$(APMIB_DIR) -lapmib  -o cJSON.o
topology.o: topology.c
	$(CC) -c topology.c $(IFLAGS) $(LDFLAGS) $(COMMON_CFLAGS) -L$(APMIB_DIR) -lapmib -o topology.o
klinkMgmt.o: klinkMgmt.c
	$(CC) -c klinkMgmt.c $(IFLAGS) $(LDFLAGS) $(COMMON_CFLAGS) -L$(APMIB_DIR) -lapmib -o klinkMgmt.o
klinkLinksListFunc.o: klinkLinksListFunc.c
	$(CC) -c klinkLinksListFunc.c $(IFLAGS) $(LDFLAGS) $(COMMON_CFLAGS) -lm -L$(APMIB_DIR) -lapmib  -o klinkLinksListFunc.o
version.o: version.c
	$(CC) -c version.c $(IFLAGS) $(LDFLAGS) $(COMMON_CFLAGS) -lm -L$(APMIB_DIR) -lapmib  -o version.o
	
romfs:
	$(ROMFSINST) $(SCHEDULE_DIR)/$(TARGET) /bin/

.PHONY:clean	
	
clean:
	-rm -f $(EXEC) *.elf *.gdb *.o $(TARGET)
