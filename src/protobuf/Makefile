CFLAGS		+= -I$(obj)/
CFLAGS		+= -fPIC -Wa,--noexecstack

proto-obj-y	+= rpc.o

proto		:= $(proto-obj-y:.o=)
proto-c		:= $(proto-obj-y:.o=.pb-c.c)
proto-h		:= $(proto-obj-y:.o=.pb-c.h)

.SECONDARY:

$(obj)/%.proto.d: $(obj)/%.proto
	$(E) "  PB DDEP " $@
	$(Q) grep "^[[:blank:]]*import[[:blank:]]" $^ | sed					  \
		-e 's/[[:blank:]]*import[[:blank:]]*//'						  \
		-e 's/[\";]//g'									  \
		-e 's/.*/$(subst /,\/,$^):$(subst /,\/,$(obj))\/&/'				| \
		uniq > $@

$(obj)/%.proto.c.d: $(obj)/%.proto | $(obj)/%.proto.d
	$(E) "  PB DEP  " $@
	$(Q) grep "^[[:blank:]]*import[[:blank:]]" $< | sed					  \
		-e 's/[[:blank:]]*import[[:blank:]]*//'						  \
		-e 's/.proto/.pb-c.c/'								  \
		-e 's/[\";]//g'									  \
		-e 's/.*/$(subst .proto,.pb-c.c,$(subst /,\/,$<)):$(subst /,\/,$(obj))\/&/'	| \
		uniq > $@

$(obj)/%.pb-c.c $(obj)/%.pb-c.h: $(obj)/%.proto $(obj)/%.proto.c.d
	$(E) "  PBCC    " $@
	$(Q) protoc-c --proto_path=$(obj)/ --c_out=$(obj)/ $<
ifeq ($(SRCARCH),arm)
	$(Q) sed -i -e 's/4294967295/0xFFFFFFFF/g' $@
	$(Q) sed -i -e 's/4294967295/0xFFFFFFFF/g' $(patsubst %.c,%.h,$@)
	$(Q) sed -i -e 's/4294967295/0xFFFFFFFF/g' $(patsubst %.h,%.c,$@)
endif

$(obj)/%.o: $(obj)/%.pb-c.c $(obj)/%.pb-c.h
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

$(obj)/%.d: $(obj)/%.pb-c.c $(obj)/%.pb-c.h
	$(E) "  DEP     " $@
	$(Q) $(CC) -M -MT $@ -MT $(patsubst %.d,%.o,$@) $(CFLAGS) $< -o $@

$(obj)/%.i: $(obj)/%.pb-c.c $(obj)/%.pb-c.h
	$(E) "  CC      " $@
	$(Q) $(CC) -E $(CFLAGS) $< -o $@

$(obj)/built-in.o: $(addprefix $(obj)/,$(proto-obj-y))
	$(E) "  LINK    " $@
	$(Q) $(LD) -r -o $@ $^

_all += $(obj)/built-in.o

ifneq ($(MAKECMDGOALS),clean)
-include $(addprefix $(obj)/,$(obj-y:.o=.proto.d))
-include $(addprefix $(obj)/,$(obj-y:.o=.proto.c.d))
endif

cleanup-y += $(obj)/*.c.d $(obj)/*.pb-c.c $(obj)/*.pb-c.h
cleanup-y += $(obj)/*.d $(obj)/*.i $(obj)/*.s $(obj)/*.o
