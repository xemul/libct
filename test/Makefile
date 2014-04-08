TESTS =	ct_create ct_enter ct_proc ct_root ct_root_enter \
	ct_create_exec ct_cgroup_basic ct_net_host \
	ct_net_veth ct_create_exec_d ct_private_subdir \
	ct_ext_mount ct_mhandle_exec_d ct_private_subdir_ns

PIGS  = file_piggy

CC = gcc
CFLAGS = -I../src/include/uapi/ -g
LDFLAGS = -lct -L../src/ -lprotobuf-c
OUTS = $(TESTS:%=%.out)

all: $(PIGS) $(TESTS)

clean:
	rm -f $(TESTS)
	rm -f $(OUTS)
	rm -f $(PIGS)

%.out: %
	./$< > $@
	@ tail -n1 $@

run: $(OUTS)

.PHONY: all clean run
