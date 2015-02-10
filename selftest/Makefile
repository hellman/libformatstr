fmtstrtester: fmtstrtester.c
	@gcc -m32 -w fmtstrtester.c -o fmtstrtester

clean:
	@rm -f *~ fmtstrtester

test: fmtstrtester
	@./selftest.py
