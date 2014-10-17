LOCAL_TESTS =	ct_create ct_enter ct_proc ct_root ct_root_enter \
	ct_create_exec ct_cgroup_basic ct_net_host \
	ct_net_veth ct_private_subdir \
	ct_ext_mount ct_private_subdir_ns \
	ct_cgroup_sub ct_service ct_kill_nons ct_pid_enter \
	ct_userns ct_caps

VZ_TESTS =

TESTS = $(LOCAL_TESTS) $(VZ_TESTS)

PIGS  = file_piggy

CC = gcc
CFLAGS = -I../src/include/uapi/ -g -Wall -Werror
LIBNLDIR = ../.shipped/libnl/lib/.libs
LDFLAGS = -Wl,--no-as-needed \
	-lct -L../src/ -Wl,-rpath,'$$ORIGIN/../src' \
	-lnl-route-3 -lnl-3 -L$(LIBNLDIR) -Wl,-rpath,'$$ORIGIN/$(LIBNLDIR)'

LOCAL_OUTS = $(LOCAL_TESTS:%=%.out)
VZ_OUTS = $(VZ_TESTS:%=%.out)
OUTS = $(TESTS:%=%.out)

local: $(PIGS) $(LOCAL_TESTS)

vz: $(VZ_TESTS)

all: $(PIGS) $(TESTS)

cleanouts:
	rm -f $(OUTS)

clean: cleanouts
	rm -f $(TESTS)
	rm -f $(PIGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

define gen-out
$(1): $(1).o
	$$(CC) -o $$@ $$^ $$(LDFLAGS)

$(1).out: $(1)
	./$$^ > $$@
	@ tail -n1 $$@
endef
$(foreach t, $(TESTS), $(eval $(call gen-out,$(t))))

run-local: cleanouts $(PIGS) $(LOCAL_OUTS)

run-vz: cleanouts $(VZ_OUTS)

run: cleanouts $(PIGS) $(OUTS)

.PHONY: all local vz clean run run-local run-vz
