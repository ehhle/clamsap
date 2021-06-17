ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

EXTRA_DIST = autogen.sh COPYING COPYING.clamav COPYING.vsa COPYING.cscompr

VERSION_DIR = clamsap-@VERSION@

cleandir:
	-rm -rf ../$(VERSION_DIR)

makedir:
	-mkdir ../$(VERSION_DIR)
	-mkdir ../$(VERSION_DIR)/src
	-mkdir ../$(VERSION_DIR)/include
	-mkdir ../$(VERSION_DIR)/config
	-mkdir ../$(VERSION_DIR)/m4

distribute_clamsap:
	-cp AUTHORS           ../$(VERSION_DIR)
	-cp ChangeLog         ../$(VERSION_DIR)
	-cp configure         ../$(VERSION_DIR)
	-cp configure.ac      ../$(VERSION_DIR)
	-cp COPYING           ../$(VERSION_DIR)
	-cp COPYING.clamav    ../$(VERSION_DIR)
	-cp COPYING.vsa       ../$(VERSION_DIR)
	-cp COPYING.cscompr   ../$(VERSION_DIR)
	-cp INSTALL           ../$(VERSION_DIR)
	-cp config.h.in       ../$(VERSION_DIR)
	-cp NEWS              ../$(VERSION_DIR)
	-cp README            ../$(VERSION_DIR)
	-cp Makefile.am       ../$(VERSION_DIR)
	-cp Makefile.in       ../$(VERSION_DIR)
	-cp clamsap.spec      ../$(VERSION_DIR)
	-cp config/*	      ../$(VERSION_DIR)/config
	-cp src/*.sln         ../$(VERSION_DIR)/src
	-cp src/*.vcproj      ../$(VERSION_DIR)/src
	-cp src/*.vcxproj*    ../$(VERSION_DIR)/src
	-cp src/*.rc          ../$(VERSION_DIR)/src
	-cp src/*.c           ../$(VERSION_DIR)/src
	-cp src/*.h           ../$(VERSION_DIR)/src	
	-cp src/Makefile.am   ../$(VERSION_DIR)/src
	-cp src/Makefile.in   ../$(VERSION_DIR)/src
	-cp m4/*              ../$(VERSION_DIR)/m4
	-cp include/*         ../$(VERSION_DIR)/include	

#install-exec-hook:
#	-ln -sf $(DESTDIR)$(libdir)/libclamdsap$(LIBEXT) $(libdir)/libsapvsa$(LIBEXT)
#	-ln -sf $(DESTDIR)$(libdir)/libclamdsap$(LIBEXT) /lib64/libsapvsa$(LIBEXT)

pack: cleandir makedir distribute_clamsap cleandir
	-cd ..; tar -zcvf $(VERSION_DIR).tar.gz $(VERSION_DIR)
