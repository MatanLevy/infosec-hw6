# WARNING: DO NOT EDIT THIS FILE!

.PHONY: all

all: q2.template q3.template q4.template

clean:
	rm -f q2.template q3.template q4.template

q2.template:
	gcc q2.c -o q2.template

q3.template:
	gcc q3.c -o q3.template

q4.template:
	gcc q4.c -o q4.template