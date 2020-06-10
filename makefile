web:
	doxygen
	cd doc/html; zip -r ../../doc .
	#rsync -ravK doc/html/ spidey2.bmsi.com:/Public/pymilter

VERS=pydspam-1.3.4
SRCTAR=$(VERS).tar.gz
V=pydspam-1_3_4

$(SRCTAR):
	git archive --format=tar.gz --prefix=$(VERS)/ -o $(SRCTAR) $(VERS)

gittar: $(SRCTAR)

