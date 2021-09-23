web:
	doxygen
	cd doc/html; zip -r ../../doc .
	rsync -ravKk doc/html/ pymilter.org:/var/www/html/milter/pydspam

VERS=pydspam-1.4.0
SRCTAR=$(VERS).tar.gz

$(SRCTAR):
	git archive --format=tar.gz --prefix=$(VERS)/ -o $(SRCTAR) $(VERS)

gittar: $(SRCTAR)

