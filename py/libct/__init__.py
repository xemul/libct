# __init__.py: python classes for libct
#
# Copyright (C) 2014 Parallels, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.

from libct import libctcapi

consts = libctcapi.consts
errors = libctcapi.errors

class LibctError(Exception):
	def __init__(self, value):
		if type(value) == type(""):
			self.descr = value
		else:
			errs = filter(lambda x: x.startswith("LCTERR_"), dir(errors))
			for err in errs:
				if value == getattr(errors, err):
					self.descr = err
					break
			else:
				self.descr = "libct error %r" % value

	def __str__(self):
		return self.descr

class Session(object):

	def __init__(self, sess):
		self._sess = sess

	def close(self):
		libctcapi.session_close(self._sess)

	def container_create(self, name):
		ct = libctcapi.container_create(self._sess, name)
		if type(ct) != type(0):
			return Container(ct)
		else:
			raise LibctError(ct)

	def container_open(self, name):
		ct = libctcapi.container_open(self._sess, name)
		if type(ct) != type(0):
			return Container(ct)
		else:
			raise LibctError(ct)

	def process_desc_create(self):
		pdesc = libctcapi.process_desc_create(self._sess)
		if type(pdesc) != type(0):
			return ProcessDesc(pdesc)
		else:
			raise LibctError(pdesc)

def open(url):
	sess = libctcapi.session_open(url)
	if type(sess) != type(0):
		return Session(sess)
	else:
		raise LibctError(sess)

def open_local():
	sess = libctcapi.session_open_local()
	if type(sess) != type(0):
		return Session(sess)
	else:
		raise LibctError(sess)

class Container(object):

	def __init__(self, ct):
		self._ct = ct

	def close(self):
		libctcapi.container_close(self._ct)

	def state(self):
		state = libctcapi.container_state(self._ct)
		return state

	def spawn_cb(self, pdesc, cb, arg):
		proc = libctcapi.container_spawn_cb(self._ct, pdesc._pdesc, cb, arg)
		if type(proc) != type(0):
			return Process(proc)
		else:
			raise LibctError(proc)

	def spawn_execv(self, pdesc, path, argv):
		proc = libctcapi.container_spawn_execv(self._ct, pdesc._pdesc, path, argv)
		if type(proc) != type(0):
			return Process(proc)
		else:
			raise LibctError(proc)

	def spawn_execve(self, pdesc, path, argv, env):
		proc = libctcapi.container_spawn_execve(self._ct, pdesc._pdesc, path, argv, env)
		if type(proc) != type(0):
			return Process(proc)
		else:
			raise LibctError(proc)

	def enter_cb(self, pdesc, cb, arg):
		proc = libctcapi.container_enter_cb(self._ct, pdesc._pdesc, cb, arg)
		if type(proc) != type(0):
			return Process(proc)
		else:
			raise LibctError(proc)

	def enter_execv(self, pdesc, path, argv, fds=None):
		proc = libctcapi.container_enter_execvfds(self._ct, pdesc._pdesc, path, argv, fds)
		if type(proc) != type(0):
			return Process(proc)
		else:
			raise LibctError(proc)

	def enter_execve(self, pdesc, path, argv, env, fds=None):
		proc = libctcapi.container_enter_execvefds(self._ct, pdesc._pdesc, path, argv, env, fds)
		if type(proc) != type(0):
			return Process(proc)
		else:
			raise LibctError(proc)

	def kill(self):
		ret = libctcapi.container_kill(self._ct)
		if ret:
			raise LibctError(ret)

	def wait(self):
		return libctcapi.container_wait(self._ct)

	def destroy(self):
		libctcapi.container_destroy(self._ct)

	def set_nsmask(self, ns_mask):
		ret = libctcapi.container_set_nsmask(self._ct, ns_mask)
		if ret:
			raise LibctError(ret)

	def controller_add(self, ctype):
		ret = libctcapi.controller_add(self._ct, ctype)
		if ret:
			raise LibctError(ret)

	def controller_configure(self, ctype, param, value):
		ret = libctcapi.controller_configure(self._ct, ctype, param, value)
		if ret:
			raise LibctError(ret)

	def uname(self, host, domain):
		ret = libctcapi.container_uname(self._ct, host, domain)
		if ret:
			raise LibctError(ret)

	def set_caps(self, mask, apply_to):
		ret = libctcapi.container_set_caps(self._ct, mask, apply_to)
		if ret:
			raise LibctError(ret)

	def set_root(self, root_path):
		ret = libctcapi.fs_set_root(self._ct, root_path)
		if ret:
			raise LibctError(ret)

	def set_private(self, fs_type, arg):
		ret = libctcapi.fs_set_private(self._ct, fs_type, arg)
		if ret:
			raise LibctError(ret)

	def add_bind_mount(self, src, dst, flags):
		ret = libctcapi.fs_add_bind_mount(self._ct, src, dst, flags)
		if ret:
			raise LibctError(ret)

	def del_bind_mount(self, dst):
		ret = libctcapi.fs_add_bind_mount(self._ct, dst)
		if ret:
			raise LibctError(ret)

	def add_mount(self, src, dst, flags, fstype, data):
		ret = libctcapi.fs_add_mount(self._ct, src, dst, flags, fstype, data)
		if ret:
			raise LibctError(ret)

	def net_add(self, ntype, arg):
		net = libctcapi.net_add(self._ct, ntype, arg)
		if type(net) != type(0):
			return Net(net)
		else:
			raise LibctError(net)

	def net_del(self, ntype, arg):
		ret = libctcapi.net_del(self._ct, ntype, arg)
		if ret:
			raise LibctError(ret)

class Net(object):

	def __init__(self, net):
		self._net = net

class ProcessDesc(object):

	def __init__(self, pdesc):
		self._pdesc = pdesc

	def copy(self):
		pdesc2 = libctcapi.process_desc_copy(self._pdesc)
		return ProcessDesc(pdesc2)

	def destroy(self):
		libctcapi.process_desc_destroy(self._pdesc)

	def setuid(self, uid):
		ret = libctcapi.process_desc_setuid(self._pdesc, uid)
		if ret:
			raise LibctError(ret)

	def setgid(self, gid):
		ret = libctcapi.process_desc_setgid(self._pdesc, gid)
		if ret:
			raise LibctError(ret)

	def set_user(self, user):
		ret = libctcapi.process_desc_set_user(self._pdesc, user)
		if ret:
			raise LibctError(ret)

	def set_groups(self, groups):
		ret = libctcapi.process_desc_set_groups(self._pdesc, groups)
		if ret:
			raise LibctError(ret)

	def set_rlimit(self, resource, soft, hard):
		ret = libctcapi.process_desc_set_rlimit(self._pdesc, resource, soft, hard)
		if ret:
			raise LibctError(ret)

	def set_lsm_label(self, label):
		ret = libctcapi.process_desc_set_lsm_label(self._pdesc, label)
		if ret:
			raise LibctError(ret)

	def set_caps(self, caps):
		ret = libctcapi.process_desc_set_caps(self._pdesc, caps)
		if ret:
			raise LibctError(ret)

	def set_pdeathsig(self, sig):
		ret = libctcapi.process_desc_set_pdeathsig(self._pdesc, deathsig)
		if ret:
			raise LibctError(ret)

	def set_fds(self, fds):
		ret = libctcapi.process_desc_set_fds(self._pdesc, fds)
		if ret:
			raise LibctError(ret)

	def set_env(self, env):
		ret = libctcapi.process_desc_set_env(self._pdesc, env)
		if ret:
			raise LibctError(ret)

class Process(object):

	def __init__(self, proc):
		self._proc = proc

	def wait(self):
		return libctcapi.process_wait(self._proc)

	def destroy(self):
		libctcapi.process_destroy(self._proc)
