/*
 * libctmodule.c: libct functions wrapppers
 *
 * Copyright (C) 2014 Parallels, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <Python.h>
#include <libct.h>
#include <libct-errors.h>

#include <stdlib.h>
#include <sched.h>

typedef struct {
	PyObject_HEAD
	libct_session_t session;
} libct_session_Object;

typedef struct {
	PyObject_HEAD
	ct_handler_t ct;
} ct_handler_Object;

typedef struct {
	PyObject_HEAD
	ct_net_t net;
} net_handler_Object;

typedef struct {
	PyObject_HEAD
	ct_process_desc_t pdesc;
} process_desc_Object;

typedef struct {
	PyObject_HEAD
	ct_process_t proc;
} process_Object;

#define CHECK_ARG_TYPE(__obj, __name, __n)					\
	do {									\
		if (!is_object_valid(__obj, __name)) {				\
			PyErr_SetString(PyExc_TypeError,			\
				"Argument " __n " must be of type " __name);	\
			return NULL;						\
		}								\
	} while (0)

static PyObject *make_object(void *cobj, const char *name)
{
	PyObject *ret;
#ifdef Py_CAPSULE_H
	ret = PyCapsule_New(cobj, name, NULL);
#else
	ret = PyCObject_FromVoidPtrAndDesc(cobj, (void *)name, NULL);
#endif
	return ret;
}

static int is_object_valid(PyObject *obj, const char *name)
{
#ifdef Py_CAPSULE_H
	if (!PyCapsule_CheckExact(obj))
		return 0;

	if (strcmp(PyCapsule_GetName(obj), name))
		return 0;

	return 1;
#else
	if (!PyCObject_Check(obj))
		return 0;

	if (strcmp((char *)PyCObject_GetDesc(obj), name))
		return 0;

	return 1;
#endif
}

static char *parse_string(PyObject *obj)
{
	char *str;

	if (!PyString_Check(obj)) {
		PyErr_SetString(PyExc_TypeError,
				"Expected string");
		return NULL;
	}

	str = strdup(PyString_AsString(obj));
	if (!str) {
		PyErr_SetString(PyExc_MemoryError,
				"Can't allocate memory");
		return NULL;
	}

	return str;
}

static char ** parse_argv(PyObject *py_list)
{
	Py_ssize_t len;
	size_t arr_size;
	char **arr;
	int i = 0, j = 0;
	PyObject *item;

	len = PyObject_Length(py_list);
	arr_size = sizeof(char *) * (len + 1);
	arr = PyMem_Malloc(arr_size);
	if (arr == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}

	memset(arr, 0, arr_size);

	for (i = 0; i < len; i++) {
		item = PySequence_GetItem(py_list, i);
		arr[i] = parse_string(item);
		if (arr[i] == NULL)
			goto err;

		strcpy(arr[i], PyString_AsString(item));
	}

	arr[i] = NULL;
	return arr;
err:
	for (j = i - 1; j > 0; j--)
		PyMem_Free(arr[j]);
	PyMem_Free(arr);
	return NULL;
}

static void free_argv(char **arr)
{
	int i = 0;

	for (i = 0; arr[i] != NULL; i ++)
		PyMem_Free(arr[i]);
	PyMem_Free(arr);
}

static ssize_t parse_string_list(PyObject *py_list, char ***arr)
{
	Py_ssize_t len;
	size_t arr_size;
	int i = 0, j = 0;
	PyObject *item;

	len = PyObject_Length(py_list);
	arr_size = sizeof(char *) * (len);
	*arr = PyMem_Malloc(arr_size);
	if (*arr == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return -1;
	}

	memset(*arr, 0, arr_size);

	for (i = 0; i < len; i++) {
		item = PySequence_GetItem(py_list, i);
		*arr[i] = parse_string(item);
		if (*arr[i] == NULL)
			goto err;

		strcpy(*arr[i], PyString_AsString(item));
	}

	return len;
err:
	for (j = i - 1; j > 0; j--)
		PyMem_Free(arr[j]);
	PyMem_Free(arr);
	return -1;
}

static ssize_t parse_int_list(PyObject *py_list, int **arr)
{
	Py_ssize_t len;
	size_t arr_size;
	int i = 0;
	PyObject *item;

	len = PyObject_Length(py_list);
	arr_size = sizeof(int) * len;
	*arr = PyMem_Malloc(arr_size);
	if (*arr == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return -1;
	}

	memset(*arr, 0, arr_size);

	for (i = 0; i < len; i++) {
		item = PySequence_GetItem(py_list, i);
		if (PyInt_Check(item)) {
			*arr[i] = PyInt_AsLong(item);
		} else if (PyLong_Check(item)) {
			*arr[i] = PyLong_AsLong(item);
		} else {
			PyErr_SetString(PyExc_MemoryError,
					"A list of integers is expected.");
			PyMem_Free(*arr);
			return -1;
		}
	}

	return len;
}

static ssize_t parse_uint_list(PyObject *py_list, unsigned int **arr)
{
	Py_ssize_t len;
	size_t arr_size;
	int i = 0;
	PyObject *item;

	len = PyObject_Length(py_list);
	arr_size = sizeof(unsigned int) * len;
	*arr = PyMem_Malloc(arr_size);
	if (*arr == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return -1;
	}

	memset(*arr, 0, arr_size);

	for (i = 0; i < len; i++) {
		item = PySequence_GetItem(py_list, i);
		if (PyInt_Check(item)) {
			*arr[i] = PyInt_AsLong(item);
		} else if (PyLong_Check(item)) {
			*arr[i] = PyLong_AsLong(item);
		} else {
			PyErr_SetString(PyExc_MemoryError,
					"A list of integers is expected.");
			PyMem_Free(*arr);
			return -1;
		}
	}

	return len;
}

static struct ct_net_veth_arg * parse_ct_net_veth(PyObject *obj)
{
	struct ct_net_veth_arg *veth;
	PyObject *temp;

	if (!PyDict_Check(obj)) {
		PyErr_SetString(PyExc_TypeError,
				"Expected dict");
		return NULL;
	}

	veth = PyMem_Malloc(sizeof(*veth));
	if (!veth) {
		PyErr_SetString(PyExc_MemoryError,
				"Can't allocate memory");
		return NULL;
	}

	memset(veth, 0, sizeof(*veth));

	temp = PyDict_GetItemString(obj, "host_name");
	if (!temp) {
		PyErr_SetString(PyExc_ValueError,
				"No 'host_name' key");
		goto err;
	}

	veth->host_name = parse_string(temp);
	if (!veth->host_name)
		goto err;

	temp = PyDict_GetItemString(obj, "ct_name");
	if (!temp) {
		PyErr_SetString(PyExc_ValueError,
				"No 'ct_name' key");
		goto err;
	}

	veth->ct_name = parse_string(temp);
	if (!veth->ct_name)
		goto err;

	return veth;
err:
	free(veth->ct_name);
	free(veth->host_name);
	PyMem_Free(veth);
	return NULL;
}

static void free_ct_net_veth(struct ct_net_veth_arg *veth)
{
	free(veth->ct_name);
	free(veth->host_name);
	PyMem_Free(veth);
}

static PyObject *
py_libct_session_open(PyObject *self, PyObject *args)
{
	char *url;
	libct_session_t session;

	if (!PyArg_ParseTuple(args, "s:libct_session_open", &url))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	session = libct_session_open(url);
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(session))
		return PyLong_FromLong(libct_handle_to_err(session));

	return make_object(session, "libct_session_t");
}

static PyObject *
py_libct_session_open_local(PyObject *self, PyObject *args)
{
	libct_session_t session;

	if (!PyArg_ParseTuple(args, ":libct_session_open_local"))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	session = libct_session_open_local();
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(session))
		return PyLong_FromLong(libct_handle_to_err(session));

	return make_object(session, "libct_session_t");
}

static PyObject *
py_libct_session_close(PyObject *self, PyObject *args)
{
	libct_session_t session;
	PyObject *py_session;

	if (!PyArg_ParseTuple(args, "O:py_libct_session_close", &py_session))
		return NULL;

	CHECK_ARG_TYPE(py_session, "libct_session_t", "1");
	session = ((libct_session_Object *)py_session)->session;

	Py_BEGIN_ALLOW_THREADS
	libct_session_close(session);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *
py_libct_container_create(PyObject *self, PyObject *args)
{
	libct_session_t session;
	PyObject *py_session;
	ct_handler_t ct;
	char *name;

	if (!PyArg_ParseTuple(args, "Os:py_libct_container_create",
				&py_session, &name))
		return NULL;

	CHECK_ARG_TYPE(py_session, "libct_session_t", "1");
	session = ((libct_session_Object *)py_session)->session;

	Py_BEGIN_ALLOW_THREADS
	ct = libct_container_create(session, name);
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(ct))
		return PyLong_FromLong(libct_handle_to_err(ct));

	return make_object(ct, "ct_handler_t");
}

static PyObject *
py_libct_container_open(PyObject *self, PyObject *args)
{
	libct_session_t session;
	PyObject *py_session;
	ct_handler_t ct;
	char *name;

	if (!PyArg_ParseTuple(args, "Os:py_libct_container_open",
				&py_session, &name))
		return NULL;

	CHECK_ARG_TYPE(py_session, "libct_session_t", "1");
	session = ((libct_session_Object *)py_session)->session;

	Py_BEGIN_ALLOW_THREADS
	ct = libct_container_open(session, name);
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(ct))
		return PyLong_FromLong(libct_handle_to_err(ct));

	return make_object(ct, "ct_handler_t");
}

static PyObject *
py_libct_container_close(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;

	if (!PyArg_ParseTuple(args, "O:py_libct_container_close", &py_ct))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	libct_container_close(ct);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *
py_libct_container_state(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	enum ct_state state;

	if (!PyArg_ParseTuple(args, "O:py_libct_container_state", &py_ct))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	state = libct_container_state(ct);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)state);
}

struct cb_arg {
	PyObject *cb;
	PyObject *arg;
};

static int ct_callback(void *arg)
{
	struct cb_arg *cb_arg = (struct cb_arg *)arg;
	PyObject *arglist;
	PyObject *result;
	PyGILState_STATE gstate;
	int ret = -1;

	gstate = PyGILState_Ensure();

	arglist = Py_BuildValue("(O)", cb_arg->arg);
	result = PyObject_CallObject(cb_arg->cb, arglist);

	Py_DECREF(arglist);

	if (result != NULL) {
		if (PyInt_Check(result))
			ret = (int)PyInt_AsLong(result);
		Py_DECREF(result);
	}

	PyGILState_Release(gstate);

	return ret;
}

static PyObject *
py_libct_container_load(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	ct_process_t proc;
	pid_t pid;

	if (!PyArg_ParseTuple(args, "Oi:py_libct_container_load",
				&py_ct, &pid))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	proc = libct_container_load(ct, pid);
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(proc))
		return PyLong_FromLong(libct_handle_to_err(proc));

	return make_object(proc, "ct_process_t");
}

static PyObject *
py_libct_container_spawn_cb(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	PyObject *py_pdesc;
	ct_handler_t ct;
	ct_process_desc_t pdesc;
	ct_process_t proc;
	struct cb_arg cb_arg;

	if (!PyArg_ParseTuple(args, "OOOO:py_libct_container_spawn_execv",
				&py_ct, &py_pdesc, &cb_arg.cb, &cb_arg.arg))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "2");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	if (!PyCallable_Check(cb_arg.cb)) {
		PyErr_SetString(PyExc_TypeError, "Parameter 2 must be callable");
		return NULL;
	}

	Py_XINCREF(cb_arg.cb);
	Py_XINCREF(cb_arg.arg);

	Py_BEGIN_ALLOW_THREADS
	proc = libct_container_spawn_cb(ct, pdesc, &ct_callback, &cb_arg);
	Py_END_ALLOW_THREADS

	Py_XDECREF(cb_arg.arg);
	Py_XDECREF(cb_arg.cb);

	if (libct_handle_is_err(proc))
		return PyLong_FromLong(libct_handle_to_err(proc));

	return make_object(proc, "ct_process_t");
}

static PyObject *
py_libct_container_spawn_execv(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	PyObject *py_pdesc;
	ct_handler_t ct;
	ct_process_desc_t pdesc;
	ct_process_t proc;
	char *path;
	PyObject *py_argv;
	char **argv;

	if (!PyArg_ParseTuple(args, "OOsO:py_libct_container_spawn_execv",
				&py_ct, &py_pdesc, &path, &py_argv))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	argv = parse_argv(py_argv);
	if (argv == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	proc = libct_container_spawn_execv(ct, pdesc, path, argv);
	Py_END_ALLOW_THREADS

	free_argv(argv);

	if (libct_handle_is_err(proc))
		return PyLong_FromLong(libct_handle_to_err(proc));

	return make_object(proc, "ct_process_t");
}

static PyObject *
py_libct_container_spawn_execve(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	PyObject *py_pdesc;
	ct_handler_t ct;
	ct_process_desc_t pdesc;
	ct_process_t proc;
	char *path;
	PyObject *py_argv;
	char **argv;
	PyObject *py_env;
	char **env;

	if (!PyArg_ParseTuple(args, "OOsOO:py_libct_container_spawn_execve",
				&py_ct, &py_pdesc, &path, &py_argv, &py_env))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	argv = parse_argv(py_argv);
	if (argv == NULL)
		return NULL;

	env = parse_argv(py_env);
	if (env == NULL) {
		free_argv(argv);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	proc = libct_container_spawn_execve(ct, pdesc, path, argv, env);
	Py_END_ALLOW_THREADS

	free_argv(argv);
	free_argv(env);

	if (libct_handle_is_err(proc))
		return PyLong_FromLong(libct_handle_to_err(proc));

	return make_object(proc, "ct_process_t");
}

static PyObject *
py_libct_container_enter_cb(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	PyObject *py_pdesc;
	ct_handler_t ct;
	ct_process_desc_t pdesc;
	ct_process_t proc;
	struct cb_arg cb_arg;

	if (!PyArg_ParseTuple(args, "OOOO:py_libct_container_enter_execv",
				&py_ct, &py_pdesc, &cb_arg.cb, &cb_arg.arg))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	if (!PyCallable_Check(cb_arg.cb)) {
		PyErr_SetString(PyExc_TypeError, "Parameter 2 must be callable");
		return NULL;
	}

	Py_XINCREF(cb_arg.cb);
	Py_XINCREF(cb_arg.arg);

	Py_BEGIN_ALLOW_THREADS
	proc = libct_container_enter_cb(ct, pdesc, &ct_callback, &cb_arg);
	Py_END_ALLOW_THREADS

	Py_XDECREF(cb_arg.arg);
	Py_XDECREF(cb_arg.cb);

	if (libct_handle_is_err(proc))
		return PyLong_FromLong(libct_handle_to_err(proc));

	return make_object(proc, "ct_process_t");
}

static PyObject *
py_libct_container_enter_execv(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	PyObject *py_pdesc;
	ct_handler_t ct;
	ct_process_desc_t pdesc;
	ct_process_t proc;
	char *path;
	PyObject *py_argv;
	char **argv;

	if (!PyArg_ParseTuple(args, "OOsO:py_libct_container_enter_execv",
				&py_ct, &py_pdesc, &path, &py_argv))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	argv = parse_argv(py_argv);
	if (argv == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	proc = libct_container_enter_execv(ct, pdesc, path, argv);
	Py_END_ALLOW_THREADS

	free_argv(argv);

	if (libct_handle_is_err(proc))
		return PyLong_FromLong(libct_handle_to_err(proc));

	return make_object(proc, "ct_process_t");
}

static PyObject *
py_libct_container_enter_execve(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	PyObject *py_pdesc;
	ct_handler_t ct;
	ct_process_desc_t pdesc;
	ct_process_t proc;
	char *path;
	PyObject *py_argv;
	char **argv;
	PyObject *py_env;
	char **env;

	if (!PyArg_ParseTuple(args, "OOsOO:py_libct_container_enter_execve",
				&py_ct, &py_pdesc, &path, &py_argv, &py_env))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	argv = parse_argv(py_argv);
	if (argv == NULL)
		return NULL;

	env = parse_argv(py_env);
	if (env == NULL) {
		free_argv(argv);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	proc = libct_container_enter_execve(ct, pdesc, path, argv, env);
	Py_END_ALLOW_THREADS

	free_argv(argv);
	free_argv(env);

	if (libct_handle_is_err(proc))
		return PyLong_FromLong(libct_handle_to_err(proc));

	return make_object(proc, "ct_process_t");
}

static PyObject *
py_libct_container_kill(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	int ret;

	if (!PyArg_ParseTuple(args, "O:py_libct_container_kill", &py_ct))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_kill(ct);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_container_wait(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	int ret;

	if (!PyArg_ParseTuple(args, "O:py_libct_container_wait", &py_ct))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_wait(ct);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_container_destroy(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;

	if (!PyArg_ParseTuple(args, "O:py_libct_container_destroy", &py_ct))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	libct_container_destroy(ct);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *
py_libct_container_set_nsmask(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	unsigned long nsmask;
	int ret;

	if (!PyArg_ParseTuple(args, "Ok:py_libct_container_set_nsmask",
				&py_ct, &nsmask))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_set_nsmask(ct, nsmask);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_container_set_nspath(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	int ns;
	char *path;
	int ret;

	if (!PyArg_ParseTuple(args, "Ois:py_libct_container_set_nspath",
				&py_ct, &ns, &path))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_set_nspath(ct, ns, path);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_container_set_sysctl(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	char *name;
	char *val;
	int ret;

	if (!PyArg_ParseTuple(args, "Oss:py_libct_container_set_sysctl",
				&py_ct, &name, &val))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_set_sysctl(ct, name, val);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_controller_add(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	enum ct_controller ctype;
	int ret;

	if (!PyArg_ParseTuple(args, "Oi:py_libct_controller_add",
				&py_ct, &ctype))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_controller_add(ct, ctype);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_controller_configure(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	enum ct_controller ctype;
	char *param;
	char *value;
	int ret;

	if (!PyArg_ParseTuple(args, "Oiss:py_libct_controller_configure",
				&py_ct, &ctype, &param, &value))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_controller_configure(ct, ctype, param, value);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_container_uname(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	char *host;
	char *domain;
	int ret;

	if (!PyArg_ParseTuple(args, "Oss:py_libct_container_uname",
				&py_ct, &host, &domain))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_uname(ct, host, domain);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_container_pause(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	int ret;

	if (!PyArg_ParseTuple(args, "O:py_libct_container_pause",
				&py_ct))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_pause(ct);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_container_resume(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	int ret;

	if (!PyArg_ParseTuple(args, "O:py_libct_container_resume",
				&py_ct))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_container_resume(ct);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_fs_set_root(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	char *root_path;
	int ret;

	if (!PyArg_ParseTuple(args, "Os:py_libct_fs_set_root",
				&py_ct, &root_path))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_fs_set_root(ct, root_path);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_fs_set_private(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	enum ct_fs_type fs_type;
	PyObject *py_arg;
	void *arg;
	int ret;

	if (!PyArg_ParseTuple(args, "OiO:py_libct_fs_set_private",
				&py_ct, &fs_type, &py_arg))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	switch (fs_type) {
	case CT_FS_NONE:
		arg = NULL;
		break;
	case CT_FS_SUBDIR:
		if (!PyString_Check(py_arg)) {
			PyErr_SetString(PyExc_TypeError,
					"Argument 2 must be string");
			return NULL;
		}

		arg = strdup(PyString_AsString(py_arg));
		if (!arg) {
			PyErr_SetString(PyExc_MemoryError,
					"Can't allocate memory");
			return NULL;
		}
		break;
	default:
		PyErr_SetString(PyExc_ValueError,
					"Invalid value for ct_fs_type");
		return NULL;
	}


	Py_BEGIN_ALLOW_THREADS
	ret = libct_fs_set_private(ct, fs_type, arg);
	Py_END_ALLOW_THREADS

	if (fs_type == CT_FS_SUBDIR)
		free(arg);

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_fs_add_bind_mount(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	char *src;
	char *dst;
	int flags;
	int ret;

	if (!PyArg_ParseTuple(args, "Ossi:py_libct_fs_add_bind_mount",
				&py_ct, &src, &dst, &flags))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_fs_add_bind_mount(ct, src, dst, flags);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_fs_del_bind_mount(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	char *dst;
	int ret;

	if (!PyArg_ParseTuple(args, "Os:py_libct_fs_del_bind_mount",
				&py_ct, &dst))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_fs_del_bind_mount(ct, dst);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_fs_add_mount(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	char *src;
	char *dst;
	int flags;
	char *fstype;
	char *data;
	int ret;

	if (!PyArg_ParseTuple(args, "Ossiss:py_libct_fs_add_mount",
				&py_ct, &src, &dst, &flags, &fstype, &data))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_fs_add_mount(ct, src, dst, flags, fstype, data);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static void *parse_ct_net_arg(PyObject *py_arg, enum ct_net_type ntype)
{
	switch (ntype) {
	case CT_NET_HOSTNIC:
	case CT_NET_VETH:
		return parse_ct_net_veth(py_arg);
	case CT_NET_NONE:
		return NULL;
	default:
		PyErr_SetString(PyExc_ValueError,
					"Invalid value for ct_net_type");
		return NULL;
	}
}

static void free_ct_net_arg(void *arg, enum ct_net_type ntype)
{
	switch (ntype) {
	case CT_NET_HOSTNIC:
	case CT_NET_VETH:
		free_ct_net_veth((struct ct_net_veth_arg *)arg);
		break;
	case CT_NET_NONE:
	default:
		break;
	}
}

static PyObject *
py_libct_net_add(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	enum ct_net_type ntype;
	PyObject *py_arg;
	void *arg;
	ct_net_t net;

	if (!PyArg_ParseTuple(args, "OiO:py_libct_net_add",
				&py_ct, &ntype, &py_arg))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	arg = parse_ct_net_arg(py_arg, ntype);
	if (PyErr_Occurred())
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	net = libct_net_add(ct, ntype, arg);
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(net))
		return PyLong_FromLong(libct_handle_to_err(net));

	free_ct_net_arg(arg, ntype);

	return make_object(net, "net_handler_t");
}

static PyObject *
py_libct_net_del(PyObject *self, PyObject *args)
{
	PyObject *py_ct;
	ct_handler_t ct;
	enum ct_net_type ntype;
	PyObject *py_arg;
	void *arg;
	int ret;

	if (!PyArg_ParseTuple(args, "OiO:py_libct_net_del",
				&py_ct, &ntype, &py_arg))
		return NULL;

	CHECK_ARG_TYPE(py_ct, "ct_handler_t", "1");
	ct = ((ct_handler_Object *)py_ct)->ct;

	arg = parse_ct_net_arg(py_arg, ntype);
	if (PyErr_Occurred())
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_net_del(ct, ntype, arg);
	Py_END_ALLOW_THREADS

	free_ct_net_arg(arg, ntype);

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_create(PyObject *self, PyObject *args)
{
	libct_session_t session;
	PyObject *py_session;
	ct_process_desc_t pdesc;

	if (!PyArg_ParseTuple(args, "O:py_libct_process_desc_create",
			&py_session))
		return NULL;

	CHECK_ARG_TYPE(py_session, "libct_session_t", "1");
	session = ((libct_session_Object *)py_session)->session;

	Py_BEGIN_ALLOW_THREADS
	pdesc = libct_process_desc_create(session);
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(pdesc))
		return PyLong_FromLong(libct_handle_to_err(pdesc));

	return make_object(pdesc, "ct_process_desc_t");
}

static PyObject *
py_libct_process_desc_copy(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc_src, pdesc_dst;

	if (!PyArg_ParseTuple(args, "O:py_libct_process_desc_copy",
			&py_pdesc))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc_src = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	pdesc_dst = libct_process_desc_copy(pdesc_src);
	Py_END_ALLOW_THREADS

	if (libct_handle_is_err(pdesc_dst))
		return PyLong_FromLong(libct_handle_to_err(pdesc_dst));

	return make_object(pdesc_dst, "ct_process_desc_t");
}

static PyObject *
py_libct_process_desc_destroy(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;

	if (!PyArg_ParseTuple(args, "O:py_libct_process_desc_destroy",
			&py_pdesc))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	libct_process_desc_destroy(pdesc);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *
py_libct_process_desc_setuid(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;
	unsigned int uid;
	int ret;

	if (!PyArg_ParseTuple(args, "OI:py_libct_process_desc_setuid",
			&py_pdesc, &uid))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_setuid(pdesc, uid);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_setgid(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;
	unsigned int gid;
	int ret;

	if (!PyArg_ParseTuple(args, "OI:py_libct_process_desc_setgid",
			&py_pdesc, &gid))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_setgid(pdesc, gid);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_user(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;
	char *user;
	int ret;

	if (!PyArg_ParseTuple(args, "Os:py_libct_process_desc_set_user",
			&py_pdesc, &user))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_user(pdesc, user);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_groups(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	PyObject *py_groups;
	ct_process_desc_t pdesc;
	unsigned int *groups = NULL;
	ssize_t len;
	int ret;

	if (!PyArg_ParseTuple(args, "OO:py_libct_process_desc_set_groups",
			&py_pdesc, &py_groups))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	len = parse_uint_list(py_groups, &groups);
	if (len < 0)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_groups(pdesc, len, groups);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_rlimit(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;
	int resource;
	uint64_t soft, hard;
	int ret;

	if (!PyArg_ParseTuple(args, "OiKK:py_libct_process_desc_set_rlimit",
			&py_pdesc, &resource, &soft, &hard))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_rlimit(pdesc, resource, soft, hard);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_lsm_label(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;
	char *label;
	int ret;

	if (!PyArg_ParseTuple(args, "Os:py_libct_process_desc_set_lsm_label",
			&py_pdesc, &label))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_lsm_label(pdesc, label);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_caps(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;
	unsigned long mask;
	unsigned int apply_to;
	int ret;

	if (!PyArg_ParseTuple(args, "OkI:py_libct_process_desc_set_caps",
			&py_pdesc, &mask, &apply_to))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_caps(pdesc, mask, apply_to);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_pdeathsig(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	ct_process_desc_t pdesc;
	int sig;
	int ret;

	if (!PyArg_ParseTuple(args, "Oi:py_libct_process_desc_set_pdeathsig",
			&py_pdesc, &sig))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_pdeathsig(pdesc, sig);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_fds(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	PyObject *py_fds;
	ct_process_desc_t pdesc;
	int *fds = NULL;
	ssize_t len;
	int ret;

	if (!PyArg_ParseTuple(args, "OO:py_libct_process_desc_set_fds",
			&py_pdesc, &py_fds))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	len = parse_int_list(py_fds, &fds);
	if (len < 0)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_fds(pdesc, fds, len);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *
py_libct_process_desc_set_env(PyObject *self, PyObject *args)
{
	PyObject *py_pdesc;
	PyObject *py_env;
	ct_process_desc_t pdesc;
	char **env = NULL;
	ssize_t len;
	int ret;

	if (!PyArg_ParseTuple(args, "OO:py_libct_process_desc_set_env",
			&py_pdesc, &py_env))
		return NULL;

	CHECK_ARG_TYPE(py_pdesc, "ct_process_desc_t", "1");
	pdesc = ((process_desc_Object *)py_pdesc)->pdesc;

	len = parse_string_list(py_env, &env);
	if (len < 0)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_desc_set_env(pdesc, env, len);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}


static PyObject *
py_libct_process_wait(PyObject *self, PyObject *args)
{
	PyObject *py_proc;
	ct_process_t proc;
	int status;
	int ret;

	if (!PyArg_ParseTuple(args, "O:py_libct_process_destroy",
			&py_proc))
		return NULL;

	CHECK_ARG_TYPE(py_proc, "ct_process_t", "1");
	proc = ((process_Object *)py_proc)->proc;

	Py_BEGIN_ALLOW_THREADS
	ret = libct_process_wait(proc, &status);
	Py_END_ALLOW_THREADS

	if (ret < 0)
		return NULL;

	return PyLong_FromLong((long)status);
}

static PyObject *
py_libct_process_destroy(PyObject *self, PyObject *args)
{
	PyObject *py_proc;
	ct_process_t proc;

	if (!PyArg_ParseTuple(args, "O:py_libct_process_destroy",
			&py_proc))
		return NULL;

	CHECK_ARG_TYPE(py_proc, "ct_process_t", "1");
	proc = ((process_Object *)py_proc)->proc;

	Py_BEGIN_ALLOW_THREADS
	libct_process_destroy(proc);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}


static PyMethodDef LibctMethods[] = {
	{"session_open",  py_libct_session_open, METH_VARARGS, "libct_session_open"},
	{"session_open_local",  py_libct_session_open_local, METH_VARARGS, "libct_session_open_local"},
	{"session_close",  py_libct_session_close, METH_VARARGS, "libct_session_close"},
	{"container_create",  py_libct_container_create, METH_VARARGS, "libct_container_create"},
	{"container_open",  py_libct_container_open, METH_VARARGS, "libct_container_open"},
	{"container_close",  py_libct_container_close, METH_VARARGS, "libct_container_close"},
	{"container_state",  py_libct_container_state, METH_VARARGS, "libct_container_state"},
	{"container_load",  py_libct_container_load, METH_VARARGS, "libct_container_load"},
	{"container_spawn_cb",  py_libct_container_spawn_cb, METH_VARARGS, "libct_container_spawn_cb"},
	{"container_spawn_execv",  py_libct_container_spawn_execv, METH_VARARGS, "libct_container_spawn_execv"},
	{"container_spawn_execve",  py_libct_container_spawn_execve, METH_VARARGS, "libct_container_spawn_execve"},
	{"container_enter_cb",  py_libct_container_enter_cb, METH_VARARGS, "libct_container_enter_cb"},
	{"container_enter_execv",  py_libct_container_enter_execv, METH_VARARGS, "libct_container_enter_execv"},
	{"container_enter_execve",  py_libct_container_enter_execve, METH_VARARGS, "libct_container_enter_execve"},
	{"container_kill",  py_libct_container_kill, METH_VARARGS, "libct_container_kill"},
	{"container_wait",  py_libct_container_wait, METH_VARARGS, "libct_container_wait"},
	{"container_destroy",  py_libct_container_destroy, METH_VARARGS, "libct_container_destroy"},
	{"container_set_nsmask",  py_libct_container_set_nsmask, METH_VARARGS, "libct_container_set_nsmask"},
	{"container_set_nspath",  py_libct_container_set_nspath, METH_VARARGS, "libct_container_set_nspath"},
	{"container_set_sysctl",  py_libct_container_set_sysctl, METH_VARARGS, "libct_container_set_sysctl"},
	{"controller_add",  py_libct_controller_add, METH_VARARGS, "libct_controller_add"},
	{"controller_configure",  py_libct_controller_configure, METH_VARARGS, "libct_controller_configure"},
	{"container_uname",  py_libct_container_uname, METH_VARARGS, "libct_container_uname"},
	{"container_pause",  py_libct_container_pause, METH_VARARGS, "libct_container_pause"},
	{"container_resume",  py_libct_container_resume, METH_VARARGS, "libct_container_resume"},
	{"fs_set_root",  py_libct_fs_set_root, METH_VARARGS, "libct_fs_set_root"},
	{"fs_set_private",  py_libct_fs_set_private, METH_VARARGS, "libct_fs_set_private"},
	{"fs_add_bind_mount",  py_libct_fs_add_bind_mount, METH_VARARGS, "libct_fs_add_bind_mount"},
	{"fs_del_bind_mount",  py_libct_fs_del_bind_mount, METH_VARARGS, "libct_fs_del_bind_mount"},
	{"fs_add_mount",  py_libct_fs_add_mount, METH_VARARGS, "libct_fs_add_mount"},
	{"net_add",  py_libct_net_add, METH_VARARGS, "libct_net_add"},
	{"net_del",  py_libct_net_del, METH_VARARGS, "libct_net_del"},
	{"process_desc_create",  py_libct_process_desc_create, METH_VARARGS, "libct_process_desc_create"},
	{"process_desc_copy",  py_libct_process_desc_copy, METH_VARARGS, "libct_process_desc_copy"},
	{"process_desc_destroy",  py_libct_process_desc_destroy, METH_VARARGS, "libct_process_desc_destroy"},
	{"process_desc_setuid",  py_libct_process_desc_setuid, METH_VARARGS, "libct_process_desc_setuid"},
	{"process_desc_setgid",  py_libct_process_desc_setgid, METH_VARARGS, "libct_process_desc_setgid"},
	{"process_desc_set_user",  py_libct_process_desc_set_user, METH_VARARGS, "libct_process_desc_set_user"},
	{"process_desc_set_groups",  py_libct_process_desc_set_groups, METH_VARARGS, "libct_process_desc_set_groups"},
	{"process_desc_set_rlimit",  py_libct_process_desc_set_rlimit, METH_VARARGS, "libct_process_desc_set_rlimit"},
	{"process_desc_set_lsm_label",  py_libct_process_desc_set_lsm_label, METH_VARARGS, "libct_process_desc_set_lsm_label"},
	{"process_desc_set_caps",  py_libct_process_desc_set_caps, METH_VARARGS, "libct_process_desc_set_caps"},
	{"process_desc_set_pdeathsig",  py_libct_process_desc_set_pdeathsig, METH_VARARGS, "libct_process_desc_set_pdeathsig"},
	{"process_desc_set_fds",  py_libct_process_desc_set_fds, METH_VARARGS, "libct_process_desc_set_fds"},
	{"process_desc_set_env",  py_libct_process_desc_set_env, METH_VARARGS, "libct_process_desc_set_env"},

	{"process_wait",  py_libct_process_wait, METH_VARARGS, "libct_process_wait"},
	{"process_destroy",  py_libct_process_destroy, METH_VARARGS, "libct_process_destroy"},

	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initlibctcapi(void)
{
	PyObject *m, *consts, *errors;
	m = Py_InitModule("libctcapi", LibctMethods);
	if (m == NULL)
		return;

	consts = Py_InitModule("libctcapi.consts", NULL);
	Py_INCREF(consts);
	PyModule_AddObject(m, "consts", consts);

	PyModule_AddIntConstant(consts, "CT_ERROR", CT_ERROR);
	PyModule_AddIntConstant(consts, "CT_STOPPED", CT_STOPPED);
	PyModule_AddIntConstant(consts, "CT_RUNNING", CT_RUNNING);

	PyModule_AddIntConstant(consts, "CTL_BLKIO", CTL_BLKIO);
	PyModule_AddIntConstant(consts, "CTL_CPU", CTL_CPU);
	PyModule_AddIntConstant(consts, "CTL_CPUACCT", CTL_CPUACCT);
	PyModule_AddIntConstant(consts, "CTL_CPUSET", CTL_CPUSET);
	PyModule_AddIntConstant(consts, "CTL_DEVICES", CTL_DEVICES);
	PyModule_AddIntConstant(consts, "CTL_FREEZER", CTL_FREEZER);
	PyModule_AddIntConstant(consts, "CTL_HUGETLB", CTL_HUGETLB);
	PyModule_AddIntConstant(consts, "CTL_MEMORY", CTL_MEMORY);
	PyModule_AddIntConstant(consts, "CTL_NETCLS", CTL_NETCLS);
	PyModule_AddIntConstant(consts, "CT_NR_CONTROLLERS", CT_NR_CONTROLLERS);

	PyModule_AddIntConstant(consts, "CAPS_BSET", CAPS_BSET);
	PyModule_AddIntConstant(consts, "CAPS_ALLCAPS", CAPS_ALLCAPS);
	PyModule_AddIntConstant(consts, "CAPS_ALL", CAPS_ALL);

	PyModule_AddIntConstant(consts, "CT_FS_NONE", CT_FS_NONE);
	PyModule_AddIntConstant(consts, "CT_FS_SUBDIR", CT_FS_SUBDIR);

	PyModule_AddIntConstant(consts, "CT_FS_RDONLY", CT_FS_RDONLY);
	PyModule_AddIntConstant(consts, "CT_FS_PRIVATE", CT_FS_PRIVATE);
	PyModule_AddIntConstant(consts, "CT_FS_BIND", CT_FS_BIND);
	PyModule_AddIntConstant(consts, "CT_FS_NOEXEC", CT_FS_NOEXEC);
	PyModule_AddIntConstant(consts, "CT_FS_NOSUID", CT_FS_NOSUID);
	PyModule_AddIntConstant(consts, "CT_FS_NODEV", CT_FS_NODEV);
	PyModule_AddIntConstant(consts, "CT_FS_STRICTATIME", CT_FS_STRICTATIME);
	PyModule_AddIntConstant(consts, "CT_FS_REC", CT_FS_REC);

	PyModule_AddIntConstant(consts, "CT_NET_NONE", CT_NET_NONE);
	PyModule_AddIntConstant(consts, "CT_NET_HOSTNIC", CT_NET_HOSTNIC);
	PyModule_AddIntConstant(consts, "CT_NET_VETH", CT_NET_VETH);

	PyModule_AddIntConstant(consts, "LIBCT_OPT_AUTO_PROC_MOUNT", LIBCT_OPT_AUTO_PROC_MOUNT);
	PyModule_AddIntConstant(consts, "LIBCT_OPT_CGROUP_SUBMOUNT", LIBCT_OPT_CGROUP_SUBMOUNT);
	PyModule_AddIntConstant(consts, "LIBCT_OPT_KILLABLE", LIBCT_OPT_KILLABLE);

	PyModule_AddIntConstant(consts, "CLONE_NEWIPC", CLONE_NEWIPC);
	PyModule_AddIntConstant(consts, "CLONE_NEWNET", CLONE_NEWNET);
	PyModule_AddIntConstant(consts, "CLONE_NEWNS", CLONE_NEWNS);
	PyModule_AddIntConstant(consts, "CLONE_NEWUTS", CLONE_NEWUTS);
	PyModule_AddIntConstant(consts, "CLONE_NEWPID", CLONE_NEWPID);

	errors = Py_InitModule("libctcapi.errors", NULL);
	Py_INCREF(errors);
	PyModule_AddObject(m, "errors", errors);

	PyModule_AddIntConstant(errors, "LCTERR_BADCTSTATE", LCTERR_BADCTSTATE);
	PyModule_AddIntConstant(errors, "LCTERR_BADTYPE", LCTERR_BADTYPE);
	PyModule_AddIntConstant(errors, "LCTERR_BADARG", LCTERR_BADARG);
	PyModule_AddIntConstant(errors, "LCTERR_NONS", LCTERR_NONS);
	PyModule_AddIntConstant(errors, "LCTERR_NOTFOUND", LCTERR_NOTFOUND);
	PyModule_AddIntConstant(errors, "LCTERR_INVARG", LCTERR_INVARG);
	PyModule_AddIntConstant(errors, "LCTERR_OPNOTSUPP", LCTERR_OPNOTSUPP);
	PyModule_AddIntConstant(errors, "LCTERR_CANTMOUNT", LCTERR_CANTMOUNT);
	PyModule_AddIntConstant(errors, "LCTERR_CGCREATE", LCTERR_CGCREATE);
	PyModule_AddIntConstant(errors, "LCTERR_CGCONFIG", LCTERR_CGCONFIG);
	PyModule_AddIntConstant(errors, "LCTERR_CGATTACH", LCTERR_CGATTACH);
	PyModule_AddIntConstant(errors, "LCTERR_BADCTRID", LCTERR_BADCTRID);
	PyModule_AddIntConstant(errors, "LCTERR_BADCTRNAME", LCTERR_BADCTRNAME);
	PyModule_AddIntConstant(errors, "LCTERR_RPCUNKNOWN", LCTERR_RPCUNKNOWN);
	PyModule_AddIntConstant(errors, "LCTERR_RPCCOMM", LCTERR_RPCCOMM);
}
