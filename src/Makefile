lib-so			+= libct

obj-y			+= libct.o
obj-y			+= session.o
obj-y			+= ct.o
obj-y			+= log.o

cflags-y		+= -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= -rdynamic

.SECONDARY:

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
