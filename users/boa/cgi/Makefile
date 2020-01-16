ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../../.config
else
include $(DIR_USERS)/.config
endif

CGI_C_SOURCE = c_demo.c
CGI_C_TARGET = c_demo

ifeq ($(CONFIG_APP_PYTHON_SUPPORT),y)
CGI_PYTHON_TARGET = python_demo
else
CGI_PYTHON_TARGET = 
endif


#APMIB_DIR=$(DIR_USERS)/boa/apmib
APMIB_DIR = ../apmib

CGI_TARGET := $(CGI_C_TARGET) $(CGI_PYTHON_TARGET)

SOURCES_SER = c_demo.c  ../src/deviceProcIf.c webTopology.c ../src/cJSON.c 

OBJS_SER = $(SOURCES_SER:.c=.o)

.PHONY: all clean
all: $(CGI_TARGET)
	cp c_demo ../html/Mesh1/c_demo.cgi

c_demo: c_demo.o webTopology.o
	$(CC) -o $@  $(OBJS_SER) -L$(APMIB_DIR) -lapmib -lm
	cp $@ ../html/Mesh1/$@.cgi

webTopology.o: webTopology.c 
	#$(CC) -c webTopology.c -L$(APMIB_DIR) -lapmib -o webTopology.o
	$(CC) -c webTopology.c -o webTopology.o $(IFLAGS) $(LDFLAGS) -L$(APMIB_DIR) -lapmib

python_demo: python_demo.py
	cp $< ../html/
	mv ../html/$@.py ../html/$@.cgi
	touch $@

clean:
	-rm -f *.o
	-rm -f $(CGI_TARGET)
	-rm -f ../html/$(addsuffix .cgi, $(CGI_TARGET))

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $<
