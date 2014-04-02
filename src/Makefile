lib-so			+= libct

obj-y			+= libct.o
obj-y			+= session.o
obj-y			+= ct.o
obj-y			+= namespaces.o
obj-y			+= cgroups.o
obj-y			+= log.o
obj-y			+= linux_kernel.o
obj-y			+= fs.o
obj-y			+= net.o
obj-y			+= libnetlink.o
obj-y			+= pb-unix.o

#
# We need protobuf
obj-e			+= $(filter-out src/protobuf/built-in.o,$(shell ls src/protobuf/*.o))

cflags-y		+= -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= -rdynamic

.SECONDARY:

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
