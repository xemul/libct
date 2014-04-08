LIBCT
=====

Libct is a containers management library which provides convenient API for
frontend programs to rule a container during its whole lifetime.

The library operates on two entities:

* session -- everyone willing to work with container must first open a
session. There are currently two types of sessions -- local, when all
containers are created as child tasks of the caller, and unix, where
the API requests are forwarded to libctd daemon, which in turn calls
respective functions withing its local session

* container -- a container. By default container is "empty", when started
it is merely a fork()-ed process. Container can be equipped with various
things, e.g.

  - Namespaces. Libcg accepts clone mask with which container is started

  - Controllers. One may configure all existing CGroup controllers inside
    which container will be started.

  - Root on a filesystem. This is a directory into which container will
    be chroot()-ed (or pivot_root()-ed if mount namespace is used).

  - Private area. This is where the files for container are. Currently
    only one type is supported -- a directory that will be bind-mounted
    into root.

  - Network. Caller may assign host NIC of veth pair's end to container
    on start.


For more details see Documentation/libct.txt, for examples -- the test/ dir.
