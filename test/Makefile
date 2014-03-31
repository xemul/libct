TESTS =	ct_create ct_enter ct_proc ct_root ct_root_enter ct_create_exec
PIGS  = file_piggy

CFLAGS = -I../src/include/uapi/
LDFLAGS = -lct -L../src/ -lprotobuf-c
OUTS = $(TESTS:%=%.out)

all: $(PIGS) $(TESTS) run

clean:
	rm -f $(TESTS)
	rm -f $(OUTS)
	rm -f $(PIGS)

%.out: %
	./$< > $@
	@ tail -n1 $@

run: $(OUTS)

.PHONY: all clean run
