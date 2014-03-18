TESTS =	ct_create ct_enter

CFLAGS = -I../src/include/uapi/
LDFLAGS = -lct -L../src/
OUTS = $(TESTS:%=%.out)
	
all: $(TESTS) run

clean:
	rm -f $(TESTS)
	rm -f $(OUTS)

%.out: %
	./$< > $@

run: $(OUTS)
	tail -n1 $(OUTS)

.PHONY: all clean run
