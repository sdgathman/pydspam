web:
	doxygen
	cd doc/html; zip -r ../../doc .
	#rsync -ravK doc/html/ spidey2.bmsi.com:/Public/pymilter

VERS=pydspam-1.3.3
SRCTAR=$(VERS).tar.gz
V=pydspam-1_3_3

$(SRCTAR):
	git archive --format=tar.gz --prefix=$(VERS)/ -o $(SRCTAR) $(VERS)

gittar: $(SRCTAR)


cvstar:
	cvs export -r $(V) -d $(VERS) pydspam
	tar cvf $(VERS).tar $(VERS)
	gzip -v $(VERS).tar
	rm -rf $(VERS)

cvstag:	
	cvs tag -F $(V)
