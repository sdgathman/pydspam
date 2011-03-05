VERS=pydspam-1.1.12
V=pydspam-1_1_12

tar:
	cvs export -r $(V) -d $(VERS) pydspam
	tar cvf $(VERS).tar $(VERS)
	gzip -v $(VERS).tar
	rm -rf $(VERS)

tag:	
	cvs tag -F $(V)
