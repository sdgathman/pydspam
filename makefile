web:
	doxygen
	cd doc/html; zip -r ../../doc .
	#rsync -ravK doc/html/ spidey2.bmsi.com:/Public/pymilter

VERS=pydspam-1.3.1
V=pydspam-1_3_1

tar:
	cvs export -r $(V) -d $(VERS) pydspam
	tar cvf $(VERS).tar $(VERS)
	gzip -v $(VERS).tar
	rm -rf $(VERS)

tag:	
	cvs tag -F $(V)
