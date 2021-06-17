## This is the shared library to be built
lib_LTLIBRARIES = libclamsap.la libclamdsap.la

## Define the source file for the module
libclamsap_la_SOURCES = vsclam.c csdecompr.c vsmime.c

libclamdsap_la_SOURCES = vsclamd.c csdecompr.c vsmime.c

libclamsap_la_LIBADD = -lclamav

libclamsap_la_CFLAGS   =
libclamdsap_la_CFLAGS  =
libclamsap_la_LDFLAGS  =
libclamdsap_la_LDFLAGS =

if LINUX
libclamsap_la_CFLAGS   += -D__NO_MATH_INLINES -pthread -fPIC -fno-strict-aliasing -fno-omit-frame-pointer -DNDEBUG -fno-strict-aliasing -pipe -fexceptions  -funsigned-char -Wall -Wno-uninitialized -Wno-long-long -Wcast-align 
libclamdsap_la_CFLAGS  += -D__NO_MATH_INLINES -pthread -fPIC -fno-strict-aliasing -fno-omit-frame-pointer -DNDEBUG -fno-strict-aliasing -pipe -fexceptions  -funsigned-char -Wall -Wno-uninitialized -Wno-long-long -Wcast-align 

libclamsap_la_LDFLAGS  += -pthread -fPIC -ldl -pthread -lrt -shared  -lc -Wl,-Bsymbolic 
libclamdsap_la_LDFLAGS += -pthread -fPIC -ldl -pthread -lrt -shared  -lc -Wl,-Bsymbolic 
endif

## Version
libclamsap_la_CFLAGS   += -DVSI2_COMPATIBLE -DCLAMSAP_VERSION=\"@VERSION@\" 
libclamdsap_la_CFLAGS  += -DVSI2_COMPATIBLE -DCLAMSAP_VERSION=\"@VERSION@\" 

libclamsap_la_LDFLAGS  += -version-info @CLAMSAP_VERSION_INFO@ 
libclamdsap_la_LDFLAGS += -version-info @CLAMSAP_VERSION_INFO@ 

## Define that an include directory is required.
INCLUDES = -I../include -I.
