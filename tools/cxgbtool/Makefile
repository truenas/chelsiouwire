# MARCH can be specified from the command line (or another Makefile) in order
# to change the default machine architecture of the build.
MARCH =

CFLAGS = -O2 -Wall

OBJS = cxgbtool.o
PROG = cxgbtool

DEFS =

# Storage
ifeq ($(storage),1)
  DEFS += -DSTORAGE -D__CSIO_FOISCSI_ENABLED__
  DEFS += -D__CSIO_COISCSI_ENABLED__
  OBJS += csio_hw.o csio_services.o csio_foiscsi.o cxgbtool_foiscsi_stor.o \
          csio_common.o cxgbtool_chnet.o
  OBJS += cxgbtool_coiscsi_stor.o cxgbtool_isns_stor.o
  CFLAGS += -I .
endif

CFLAGS += ${DEFS} ${MARCH}
LDFLAGS += ${MARCH}

SHARED_LIB = libcsio_um.so
LSOURCE = csio_hw.c csio_services.c csio_foiscsi.c cxgbtool_foiscsi_stor.c \
          csio_common.c cxgbtool_chnet.c
LSOURCE += cxgbtool_coiscsi_stor.c cxgbtool_isns_stor.c

all: ${PROG}

${PROG}: ${OBJS}
cxgbtool.o: reg_defs.c reg_defs_t3.c reg_defs_t3b.c reg_defs_t3c.c \
	reg_defs_t4.c reg_defs_t4vf.c reg_defs_t5.c reg_defs_t6.c cxgbtool.h

install: ${PROG}
	install -m 755 cxgbtool $(PREFIX)/sbin
	gzip -c cxgbtool.8 > cxgbtool.8.gz
	@if [ -d $(PREFIX)/usr/share/man ];\
		then install -m 444 cxgbtool.8.gz $(PREFIX)/usr/share/man/man8;\
	elif [ -d $(PREFIX)/usr/man ];\
		then install -m 444 cxgbtool.8.gz $(PREFIX)/usr/man/man8;\
	fi
	@/bin/rm -f cxgbtool.8.gz
	gzip -c cxgbtool-stor.8 > cxgbtool-stor.8.gz
	@if [ -d $(PREFIX)/usr/share/man ];\
		then install -m 444 cxgbtool-stor.8.gz $(PREFIX)/usr/share/man/man8;\
	elif [ -d $(PREFIX)/usr/man ];\
		then install -m 444 cxgbtool-stor.8.gz $(PREFIX)/usr/man/man8;\
	fi
	@/bin/rm -f cxgbtool-stor.8.gz
 
lib:
	$(CC) $(CFLAGS) -DSTORAGE -D__CSIO_FOISCSI_ENABLED__ -fPIC -I . $(LDFLAGS) -shared $(LSOURCE) -o $(SHARED_LIB)

clean:
	/bin/rm -f ${PROG} ${OBJS} ${SHARED_LIB}

uninstall:
	@if [ -f $(PREFIX)/usr/share/man/cxgbtool.8.gz ];\
		then /bin/rm -f $(PREFIX)/usr/share/man/cxgbtool.8.gz;\
	elif [ -f $(PREFIX)/usr/man ];\
		then /bin/rm -f $(PREFIX)/usr/man/cxgbtool.8.gz;\
	fi
	@if [ -f $(PREFIX)/usr/share/man/cxgbtool-stor.8.gz ];\
		then /bin/rm -f $(PREFIX)/usr/share/man/cxgbtool-stor.8.gz;\
	elif [ -f $(PREFIX)/usr/man ];\
		then /bin/rm -f $(PREFIX)/usr/man/cxgbtool-stor.8.gz;\
	fi	
	@if [ -f $(PREFIX)/sbin/cxgbtool ];\
		then /bin/rm -f $(PREFIX)/sbin/cxgbtool;\
	fi

prep:
