DISTCLEANFILES = Makefile.in \
ecapguardian.conf \
ecapguardianf1.conf

SUBDIRS = lists downloadmanagers authplugins .

if NEED_CSCONFIGS
SUBDIRS += contentscanners
endif

FLISTS = ecapguardian.conf ecapguardianf1.conf

EXTRA_DIST = ecapguardian.conf.in ecapguardianf1.conf.in

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(DGCONFDIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DGCONFDIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(DGCONFDIR)/$$l; \
	done

uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(DGCONFDIR)/$$l ; \
	done

