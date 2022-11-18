import ctypes as _c
import enum as _enum
import os as _os
import os.path as _path
import threading
import functools
import errno
import socket
import itertools
import dataclasses
import shutil
from typing import *
try:
  from typing import Literal
except ImportError:
  from typing_extensions import Literal

def ok(x):
  return x is not None

def make_posix_errno():
  ns = _enum.EnumMeta.__prepare__('POSIX_ERRNO', (_enum.IntEnum,))
  ns.update({v: k for k, v in errno.errorcode.items()})
  ns._member_names.extend(errno.errorcode.values())
  cls = type('POSIX_ERRNO', (_enum.IntEnum,), ns)
  return cls

POSIX_ERRNO = make_posix_errno()

NULL = None

#intptr_t = _c.c_ssize_t
#uintptr_t = _c.c_size_t

intptr_t = _c.c_long
uintptr_t = _c.c_ulong

int_t = _c.c_int
float_t = _c.c_float
double_t = _c.c_double
bool_t = _c.c_bool
void_p = _c.c_void_p
char_p = _c.c_char_p

rktio_bool_t = bool_t
rktio_int64_t = _c.c_int64

def joinext(filepath, ext):
  base, tail = _os.path.splitext(filepath)
  return base + ext

def abspath(filepath, directory=None):
  if not ok(directory):
    directory = _os.getcwd()
  filepath = _path.normapth(filepath)
  filepath = _path.abspath(filepath)
  return _path.relpath(filepath, directory)

def which(filepath):
  if ok(it := shutil.which(filepath)):
    return it
  for ext in ["", ".so", ".dylib", ".dll"]:
    if ok(it := shutil.which(joinext(filepath, ext))):
      return it

def resolve(filepath, directories):
  if ok(it := which(filepath)):
    return it
  for directory in directories:
    if ok(it := which(abspath(filepath, directory=directory))):
      return it
    fullpath = abspath(filepath, directory=_path.dirname(__file__))

def whichlib(filepath):
  directories = []
  for directory in [_path.dirname(__file__), _os.getcwd()]:
    for subdir in ["", ".libs"]:
      directories.append(_path.join(directory, subdir, filepath))
  return resolve(filepath, directories)


def loadlib(filename, error=False):
  filename = whichlib(filename) or filename
  try:
    return _c.cdll.LoadLibrary(filename)
  except OSError:
    if error:
      raise

# librktio = _loadlib("librktio.dylib")
# librktio = librktio or _loadlib("librktio.so")
# librktio = librktio or _loadlib(".libs/librktio.so", error=True)
librktio = loadlib("librktio")

def unwrap(x):
  return getattr(x, "_as_parameter_", x)

def asptr(ptr, kind):
  if ptr:
    return _c.cast(asvoidp(kind), _c.POINTER(kind))

def asvoidp(ptr):
  if p := unwrap(ptr):
    return _c.cast(p, void_p)

def ascharp(ptr):
  if p := unwrap(ptr):
    return _c.cast(p, char_p)

def asbytes(ptr) -> Optional[bytes]:
  if isinstance(ptr, bytes):
    return ptr
  if isinstance(ptr, str):
    try:
      return ptr.encode('utf8')
    except UnicodeEncodeError:
      return ptr.encode('latin1')
  if p := ascharp(ptr):
    return p.value

def asutf8(ptr):
  if ok(b := asbytes(ptr)):
    return b.decode('utf8')

def maybeutf8(ptr):
  if ok(b := asbytes(ptr)):
    try:
      return b.decode('utf8')
    except UnicodeDecodeError:
      return b

def address(ptr):
  if p := asvoidp(ptr):
    return p.value

def isnull(ptr):
  return address(ptr) is None

def check_bool(val, *args):
  if isinstance(val, bool):
    return val
  if isinstance(val, int):
    if val in [0, 1]:
      return bool(val)
  raise ValueError("check_bool failed", (val, *args))

def in_path(s):
  return _os.fsencode(s)

def check_bytes(ptr, *args):
  if args:
    try:
      return asbytes(check_rktio_ok_t(ptr, *args))
    finally:
      rktio_free(ptr)
  else:
    return asbytes(check_rktio_ok_t(ptr, *args))

def check_path(ptr, *args):
  if args:
    try:
      return check_path(asbytes(check_rktio_ok_t(ptr, *args)))
    finally:
      rktio_free(ptr)
  else:
    try:
      return _os.fsdecode(ptr)
    except TypeError:
      raise ValueError("check_path failed", (ptr, *args))

def check_directory_path(ptr, *args):
  if ok(path := check_path(ptr, *args)):
    if not path:
      path = '.'
    if not path.endswith(_os.path.sep):
      path += _os.path.sep
    return path

def typecheck(ptr, kind, label):
  if not isinstance(ptr, kind):
    raise TypeError(f"not a {label}: {ptr!r}")
  return ptr

def typecheck_or_null(ptr, kind, label):
  if ptr:
    typecheck(ptr, kind, label)
    return ptr

def check_type(p, kind, label):
  typecheck(unwrap(p), kind, label)
  return p

def check_type_or_null(p, kind, label):
  if ptr := unwrap(p):
    typecheck(ptr, kind, label)
    return p

def check_int(v, label="<argument>"):
  check_type(v, (int, int_t, intptr_t), label)
  return int(unwrap(v))

class CParameter:
  def __init__(self, p):
    self._as_parameter_ = p

  def unwrap(self):
    return self._as_parameter_

  def unset(self):
    self._as_parameter_ = None

  def __bool__(self):
    return ok(self.unwrap())

  def __del__(self):
    self.dispose()

  def dispose(self):
    self.detach()

  def detach(self):
    if ok(it := self.unwrap()):
      noisy_log("detach", self, it)
      self.unset()
      return it

  def __eq__(self, rhs):
    if unwrap(self) == unwrap(rhs):
      return True
    if address(unwrap(self)) == address(unwrap(rhs)):
      return True
    if (not self) == (not rhs):
      return True
    return False

  def __neq__(self, rhs):
    return not (self == rhs)

def detach(x, cls=CParameter):
  if isinstance(x, cls):
    return x.detach()

def release(x):
  if hasattr(x, "dispose"):
    x.dispose()

def noisy_log(name, *args, **kws):
  if kws:
    print(name, *args, kws)
  else:
    print(name, *args)

def noisy_call(name, f, *args, **kws):
  noisy_log(name, *args, **kws)
  return f(*args, **kws)

def capi_call(name, *args, **kws):
  if not name.startswith("capi_"):
    name = "capi_" + name
  f = globals()[name]
  return noisy_call(name, f, *args, **kws)

# /*************************************************/
# /* Initialization and general datatypes          */
# 
# typedef struct rktio_t rktio_t;
# /* A rktio_t value represents an instance of the Racket I/O system.
#    Almost every `rktio_...` function takes it as the first argument. */
class rktio_t(_c.Structure):
  """A rktio_t value represents an instance of the Racket I/O system.
  Almost every `rktio_...` function takes it as the first argument."""

rktio_p = _c.POINTER(rktio_t)

def check_rktio_p(p, *args):
  return check_type(p, rktio_p, "rktio_p")

def check_rktio_p_or_null(p, *args):
  return check_type_or_null(p, rktio_p, "rktio_p")

class Rktio(CParameter):
  """A rktio_t value represents an instance of the Racket I/O system.
  Almost every `rktio_...` function takes it as the first argument."""

  def __init__(self, p):
    typecheck_or_null(p, rktio_p, "rktio_p")
    super().__init__(p)

  def dispose(self):
    if p := unwrap(self):
      rktio_destroy(self)
    super().dispose()


# RKTIO_EXTERN rktio_t *rktio_init(void);
# /* Call `rktio_init` before anything else. The first call to
#    `rktio_init` must return before any additional calls (in other
#    threads), but there's no ordering requirement after that. 
#    If the result is NULL, then there's no way to get an error
#    code, so assume `RKTIO_ERROR_INIT_FAILED`. */
capi_rktio_init = librktio.rktio_init
capi_rktio_init.argtypes = []
capi_rktio_init.restype = rktio_p
capi_rktio_init.errcheck = check_rktio_p
def rktio_init() -> Rktio:
  return Rktio(capi_call("capi_rktio_init"))

# RKTIO_EXTERN void rktio_destroy(rktio_t *rktio);
# /* Call `rktio_destroy` as the last thing. Everything else must be
#    explicitly deallocated/closed/forgotten before calling
#    `rktio_destroy`. */
capi_rktio_destroy = librktio.rktio_destroy
capi_rktio_destroy.argtypes = [rktio_p]
capi_rktio_destroy.restype = None
def rktio_destroy(rktio: Rktio):
  if ok(self := detach(rktio, Rktio)):
    rktio = self
  if rktio:
    return capi_call("capi_rktio_destroy", check_rktio_p(rktio))

# RKTIO_EXTERN void rktio_free(void *p);
# /* Normally equivalent to `free`, but ensures the same `malloc`/`free`
#    that rktio function use. */
capi_rktio_free = librktio.rktio_free
capi_rktio_free.argtypes = [void_p]
capi_rktio_free.restype = None
def rktio_free(p):
  if ok(self := detach(p)):
    p = self
  if p:
    return capi_call("capi_rktio_free", p)


def funcptr_to_name(ptr, trim=False):
  return ({id(v): k[len("capi_rktio_" if trim else ""):] for k, v in globals().items() if k.startswith("capi_rktio_")}).get(id(ptr), "<unknown>")

class RktioException(Exception):
  def __init__(self, msg=None, *args, code=None, name=None):
    if code is not None:
      # code = RKTIO_ERROR(code)
      if name is None:
        name = code.name
    if msg is None:
      msg = name
    elif name is not None:
      msg = f"{name}: {msg}"
    super().__init__(msg, *args)
    self.code = code
    self.name = name


# typedef int rktio_ok_t;
rktio_ok_t = int_t
# /* A result of this type is 0 for failure (in which case an error is
#    available from `rktio_get_last_error`) and 1 for success. */

def rktio_check_error(rktio: rktio_p, *rest):
  if code := rktio_get_last_error(rktio):
    msg = rktio_get_last_error_string(rktio)
    if rest:
      result, *rest = rest
      if rest:
        func, args = rest
        return RktioException(msg, (result, funcptr_to_name(func), args), code=code)
    return RktioException(msg, rest, code=code)

def rktio_error(result, *rest, rktio=None):
  if rktio is None:
    func, args = rest
    rktio = args[0]
  if err := rktio_check_error(rktio, result, *rest):
    raise err

def check_valid(rktio, result, *rest):
  if not result:
    if result != b'' and result != '' and not isinstance(result, _c._Pointer):
      rktio_error(result, *rest, rktio=rktio)
      raise AssertionError("no rktio_error, but result failed", result, *rest)


def check_rktio_ok_t(result, *rest):
  rktio_error(result, *rest)
  check_valid(None, result, *rest)
  return result

def out_rktio_value(ptr, kind, *rest):
  out = _c.cast(check_rktio_ok_t(ptr, *rest), kind)
  assert out
  return out.contents.value

# def out_int(ptr, *rest):
#   return out_rktio_value(ptr, intptr_t, *rest)

# typedef int rktio_tri_t;
# /* A result of this type is a boolean, but a `...ERROR` value means
#    that an error value is available from `rktio_get_last_error`. */
rktio_tri_t = int_t

# typedef int rktio_bool_t;
# /* 0 or 1. */
rktio_bool_t = bool_t

# typedef unsigned short rktio_char16_t;
# /* A UTF-16 code unit. A `rktio_char16_t *` is meant to be the same as
#    `wchar_t *` on Windows. */

# typedef const char *rktio_const_string_t;
# /* An argument that is a NUL-terminated string, as opposed to a buffer
#    where a length is provided separately and doesn't need to be
#    NUL-terminated. */
rktio_const_string_t = char_p

# /*************************************************/
# /* DLL paths                                     */

# RKTIO_EXTERN void rktio_set_dll_path(rktio_char16_t *p);
# /* Sets a path to search for loading DLLs, such as `iconv` on Windows.
#    This function departs from all the usual conventions: the given
#    path is in wide-character format, it's not copied, and it's not
#    specific to a `rktio_t` instance. */

# RKTIO_EXTERN rktio_char16_t *rktio_get_dll_path(rktio_char16_t *p);
# /* Combines a path prevously registered with `rktio_set_dll_path` with
#    the given filename. The result is allocated (as should be
#    deallocated) as usual. */

# /*************************************************/
# /* Reading and writing files                     */
# 
# typedef struct rktio_fd_t rktio_fd_t;
class rktio_fd_t(_c.Structure):
  pass

rktio_fd_p = _c.POINTER(rktio_fd_t)

def check_rktio_fd_p(p, *args):
  return check_type(p, rktio_fd_p, "rktio_fd_p")

def check_rktio_fd_p_or_null(p, *args):
  return check_type_or_null(p, rktio_fd_p, "rktio_fd_p")

class RktioFd(CParameter):
  def __init__(self, rktio, fd, *, close=False):
    typecheck_or_null(fd, rktio_fd_p, "rktio_fd_p")
    super().__init__(fd)
    self._rktio = check_rktio_p(rktio)
    self._close = close

  def unset(self):
    super().unset()
    self._rktio = None

  def __bool__(self):
    if not self._rktio:
      return False
    return super().__bool__()

  def dispose(self):
    if self and self._close:
      rktio_close(self._rktio, self)
    super().dispose()

rktio__released_fds = globals().setdefault("rktio__released_fds", set())
rktio__released_fds_lock = globals().setdefault("rktio__released_fds_lock", threading.RLock())

def rktio__fd_lock():
  return rktio__released_fds_lock

def rktio__fd_closed(fd: rktio_fd_p) -> bool:
  ptr = check_rktio_fd_p_or_null(fd)
  if not ok(ptr):
    return True
  if not (addr := address(ptr)):
    return True
  if addr in rktio__released_fds:
    return True
  return False

def rktio__fd_on_new(r: rktio_p, fd: rktio_fd_p, close: bool = False):
  # ptr = check_rktio_fd_p(fd)
  # if addr := address(ptr):
  #   try:
  #     rktio__released_fds.remove(addr)
  #   except KeyError:
  #     pass
  return RktioFd(r, fd, close=close)

def rktio__fd_on_close(fd: rktio_fd_p):
  # ptr = check_rktio_fd_p(fd)
  # if addr := address(ptr):
  #   rktio__released_fds.add(addr)
  return fd
  

class RKTIO_OPEN(_enum.IntFlag):
  # /* Mode flags shared in part by `rktio_open` and `rktio_system_fd`. */
  # 
  # /* Accepted by both, but `RKTIO_OPEN_READ` and `RKTIO_OPEN_WRITE` are
  #    merely advisory for `rktio_system_fd` */
  # #define RKTIO_OPEN_READ        (1<<0)
  # #define RKTIO_OPEN_WRITE       (1<<1)
  # #define RKTIO_OPEN_TEXT        (1<<2)
  RKTIO_OPEN_READ = _enum.auto()
  RKTIO_OPEN_WRITE = _enum.auto()
  RKTIO_OPEN_TEXT = _enum.auto()
  # 
  # /* Used for `rktio_open` with `RKTIO_OPEN_WRITE`: */
  # #define RKTIO_OPEN_TRUNCATE    (1<<3)
  # #define RKTIO_OPEN_APPEND      (1<<4)
  # #define RKTIO_OPEN_MUST_EXIST  (1<<5)
  # #define RKTIO_OPEN_CAN_EXIST   (1<<6)
  RKTIO_OPEN_TRUNCATE = _enum.auto()
  RKTIO_OPEN_APPEND = _enum.auto()
  RKTIO_OPEN_MUST_EXIST = _enum.auto()
  RKTIO_OPEN_CAN_EXIST = _enum.auto()
  # /* `RKTIO_OPEN_APPEND` implies `RKTIO_OPEN_CAN_EXIST` */
  # 
  # /* Used for `rktio_system_fd`: */
  # #define RKTIO_OPEN_SOCKET      (1<<7)
  # #define RKTIO_OPEN_UDP         (1<<8)
  # #define RKTIO_OPEN_REGFILE     (1<<9)
  # #define RKTIO_OPEN_NOT_REGFILE (1<<10)
  RKTIO_OPEN_SOCKET      = _enum.auto()
  RKTIO_OPEN_UDP         = _enum.auto()
  RKTIO_OPEN_REGFILE     = _enum.auto()
  RKTIO_OPEN_NOT_REGFILE = _enum.auto()
  # /* If neither RKTIO_OPEN_REGILE nor RKTIO_OPEN_NOT_REGILE
  #    are specified, then the value is inferred by `rtkio_system_fd`. */
  # #define RKTIO_OPEN_DIR         (1<<11)
  # #define RKTIO_OPEN_NOT_DIR     (1<<12)
  RKTIO_OPEN_DIR         = _enum.auto()
  RKTIO_OPEN_NOT_DIR     = _enum.auto()
  # /* Inferred when neither is specified and when `RKTIO_OPEN_[NOT_]REGFILE`
  #    is also inferred. */
  # #define RKTIO_OPEN_INIT        (1<<13)
  RKTIO_OPEN_INIT        = _enum.auto()
  # /* Make `rtkio_system_fd` set a socket as nonblocking, etc. */
  # #define RKTIO_OPEN_OWN         (1<<14)
  RKTIO_OPEN_OWN         = _enum.auto()
  # /* Make `rtkio_system_fd` record a socket for reliable clean up on pre-NT Windows. */

RKTIO_OPEN_READ = RKTIO_OPEN.RKTIO_OPEN_READ
RKTIO_OPEN_WRITE = RKTIO_OPEN.RKTIO_OPEN_WRITE
RKTIO_OPEN_TEXT = RKTIO_OPEN.RKTIO_OPEN_TEXT
RKTIO_OPEN_TRUNCATE = RKTIO_OPEN.RKTIO_OPEN_TRUNCATE
RKTIO_OPEN_APPEND = RKTIO_OPEN.RKTIO_OPEN_APPEND
RKTIO_OPEN_MUST_EXIST = RKTIO_OPEN.RKTIO_OPEN_MUST_EXIST
RKTIO_OPEN_CAN_EXIST = RKTIO_OPEN.RKTIO_OPEN_CAN_EXIST
RKTIO_OPEN_SOCKET = RKTIO_OPEN.RKTIO_OPEN_SOCKET
RKTIO_OPEN_UDP = RKTIO_OPEN.RKTIO_OPEN_UDP
RKTIO_OPEN_REGFILE = RKTIO_OPEN.RKTIO_OPEN_REGFILE
RKTIO_OPEN_NOT_REGFILE = RKTIO_OPEN.RKTIO_OPEN_NOT_REGFILE
RKTIO_OPEN_DIR = RKTIO_OPEN.RKTIO_OPEN_DIR
RKTIO_OPEN_NOT_DIR = RKTIO_OPEN.RKTIO_OPEN_NOT_DIR
RKTIO_OPEN_INIT = RKTIO_OPEN.RKTIO_OPEN_INIT
RKTIO_OPEN_OWN = RKTIO_OPEN.RKTIO_OPEN_OWN

assert RKTIO_OPEN_INIT == (1<<13)
assert RKTIO_OPEN_OWN == (1<<14)

#RKTIO_EXTERN rktio_fd_t *rktio_system_fd(rktio_t *rktio, intptr_t system_fd, int modes);
#/* A socket (as opposed to other file descriptors) registered this way
#   should include include `RKTIO_OPEN_SOCKET` and be non-blocking or
#   use `RKTIO_OPEN_INIT`. */

capi_rktio_system_fd = librktio.rktio_system_fd
capi_rktio_system_fd.argtypes = [rktio_p, intptr_t, int_t]
capi_rktio_system_fd.restype = rktio_fd_p
capi_rktio_system_fd.errcheck = check_rktio_ok_t
def rktio_system_fd(rktio, system_fd: int, modes: RKTIO_OPEN):
  """A socket (as opposed to other file descriptors) registered this way
  should include include `RKTIO_OPEN_SOCKET` and be non-blocking or
  use `RKTIO_OPEN_INIT`."""
  fd = check_int(system_fd, "system_fd")
  modes = int(RKTIO_OPEN(modes))
  out = capi_call("rktio_system_fd", check_rktio_p(rktio), fd, modes)
  #return out
  return RktioFd(rktio, out)

#RKTIO_EXTERN_NOERR intptr_t rktio_fd_system_fd(rktio_t *rktio, rktio_fd_t *rfd);
#/* Extracts a native file descriptor or socket. A file descriptor must
#   not be in pending-open mode as reported by `rktio_fd_is_pending_open`. */
capi_rktio_fd_system_fd = librktio.rktio_fd_system_fd
capi_rktio_fd_system_fd.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_system_fd.restype = intptr_t
# capi_rktio_fd_system_fd.errcheck = out_int
def rktio_fd_system_fd(rktio, rfd):
  """Extracts a native file descriptor or socket. A file descriptor must
  not be in pending-open mode as reported by `rktio_fd_is_pending_open`."""
  out = capi_call("rktio_fd_system_fd", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

#RKTIO_EXTERN rktio_bool_t rktio_fd_is_regular_file(rktio_t *rktio, rktio_fd_t *rfd);
#RKTIO_EXTERN rktio_bool_t rktio_fd_is_directory(rktio_t *rktio, rktio_fd_t *rfd);
#RKTIO_EXTERN rktio_bool_t rktio_fd_is_socket(rktio_t *rktio, rktio_fd_t *rfd);
#RKTIO_EXTERN rktio_bool_t rktio_fd_is_udp(rktio_t *rktio, rktio_fd_t *rfd);
#RKTIO_EXTERN rktio_bool_t rktio_fd_is_terminal(rktio_t *rktio, rktio_fd_t *rfd);
#/* The functions mostly report values of recorded mode flags. */

capi_rktio_fd_is_regular_file = librktio.rktio_fd_is_regular_file
capi_rktio_fd_is_regular_file.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_is_regular_file.restype = rktio_bool_t
def rktio_fd_is_regular_file(rktio, rfd):
  out = capi_call("rktio_fd_is_regular_file", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

capi_rktio_fd_is_directory = librktio.rktio_fd_is_directory
capi_rktio_fd_is_directory.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_is_directory.restype = rktio_bool_t
def rktio_fd_is_directory(rktio, rfd):
  out = capi_call("rktio_fd_is_directory", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

capi_rktio_fd_is_socket = librktio.rktio_fd_is_socket
capi_rktio_fd_is_socket.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_is_socket.restype = rktio_bool_t
def rktio_fd_is_socket(rktio, rfd):
  out = capi_call("rktio_fd_is_socket", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

capi_rktio_fd_is_udp = librktio.rktio_fd_is_udp
capi_rktio_fd_is_udp.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_is_udp.restype = rktio_bool_t
def rktio_fd_is_udp(rktio, rfd):
  out = capi_call("rktio_fd_is_udp", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

capi_rktio_fd_is_terminal = librktio.rktio_fd_is_terminal
capi_rktio_fd_is_terminal.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_is_terminal.restype = rktio_bool_t
def rktio_fd_is_terminal(rktio, rfd):
  out = capi_call("rktio_fd_is_terminal", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

#RKTIO_EXTERN rktio_bool_t rktio_fd_is_text_converted(rktio_t *rktio, rktio_fd_t *rfd);
#/* Reports whether `RKTIO_OPEN_TEXT` was used and has an effect. The
#   `RKTIO_OPEN_TEXT` flag has an effect only on Windows. */

#RKTIO_EXTERN rktio_bool_t rktio_fd_is_pending_open(rktio_t *rktio, rktio_fd_t *rfd);
#/* Reports whether `rfd` will block on writing because it corresponds
#   to the write end of a fifo that has no open reader. In that case,
#   `rktio_fd_system_fd` cannot report a file descriptor and `rktio_ltps_add`
#   will error with `RKTIO_ERROR_UNSUPPORTED`. */
capi_rktio_fd_is_pending_open = librktio.rktio_fd_is_pending_open
capi_rktio_fd_is_pending_open.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_is_pending_open.restype = rktio_bool_t
def rktio_fd_is_pending_open(rktio, rfd):
  out = capi_call("rktio_fd_is_pending_open", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

#RKTIO_EXTERN_NOERR int rktio_fd_modes(rktio_t *rktio, rktio_fd_t *rfd);
#/* Returns all of the recorded mode flags, including those provided to
#   `rktio_system_fd` and those that are inferred. The
#   `RKTIO_OPEN_INIT` flag is not recorded, however. */
capi_rktio_fd_modes = librktio.rktio_fd_modes
capi_rktio_fd_modes.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_modes.restype = int_t
capi_rktio_fd_modes.errcheck = check_rktio_ok_t
def rktio_fd_modes(rktio, rfd):
  """Returns all of the recorded mode flags, including those provided to
  `rktio_system_fd` and those that are inferred. The
  `RKTIO_OPEN_INIT` flag is not recorded, however."""
  out = capi_call("rktio_fd_modes", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return RKTIO_OPEN(out)

#RKTIO_EXTERN rktio_fd_t *rktio_open(rktio_t *rktio, rktio_const_string_t src, int modes);
#/* Can report `RKTIO_ERROR_DOES_NOT_EXIST` in place of a system error
#   in read mode, and can report `RKTIO_ERROR_IS_A_DIRECTORY`,
#   `RKTIO_ERROR_EXISTS`, or `RKTIO_ERROR_ACCESS_DENIED` in place of a
#   system error in write mode. On Windows, can report
#   `RKTIO_ERROR_UNSUPPORTED_TEXT_MODE`. If `modes` has `RKTIO_OPEN_WRITE`
#   without `RKTIO_OPEN_READ`, then the result may be a file descriptor
#   in pending-open mode until the read end is opened. */
capi_rktio_open = librktio.rktio_open
capi_rktio_open.argtypes = [rktio_p, rktio_const_string_t, int_t]
capi_rktio_open.restype = rktio_fd_p
capi_rktio_open.errcheck = check_rktio_ok_t
def rktio_open(rktio: rktio_p, src: _os.PathLike, modes: RKTIO_OPEN):
  """Can report `RKTIO_ERROR_DOES_NOT_EXIST` in place of a system error
  in read mode, and can report `RKTIO_ERROR_IS_A_DIRECTORY`,
  `RKTIO_ERROR_EXISTS`, or `RKTIO_ERROR_ACCESS_DENIED` in place of a
  system error in write mode. On Windows, can report
  `RKTIO_ERROR_UNSUPPORTED_TEXT_MODE`. If `modes` has `RKTIO_OPEN_WRITE`
  without `RKTIO_OPEN_READ`, then the result may be a file descriptor
  in pending-open mode until the read end is opened."""
  with rktio__fd_lock():
    fd = capi_call("capi_rktio_open", check_rktio_p(rktio), _os.fsencode(src), int(RKTIO_OPEN(modes)))
    return rktio__fd_on_new(rktio, fd, close=True)


#RKTIO_EXTERN rktio_fd_t *rktio_open_with_create_permissions(rktio_t *rktio,
#                                                            rktio_const_string_t src,
#                                                            int modes, int perm_bits);
#/* Like `rktio_open`, but accepts permission bits that are used if the
#   file is created (which is only relevant if `modes` includes
#   `RKTIO_OPEN_WRITE`). On Unix, perm_bits are adjusted by a umask.
#   Otherwise, permission bits are treated in the same way as
#   by `rktio_set_file_or_directory_permissions`. */
##define RKTIO_DEFAULT_PERM_BITS 0666


#RKTIO_EXTERN rktio_ok_t rktio_close(rktio_t *rktio, rktio_fd_t *fd);
#/* Can report `RKTIO_ERROR_EXISTS` in place of system error,
#   and can report `RKTIO_ERROR_UNSUPPORTED_TEXT_MODE` on Windows.
#   See also `rktio_write` and `rktio_poll_write_flushed`. */
capi_rktio_close = librktio.rktio_close
capi_rktio_close.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_close.restype = rktio_ok_t
capi_rktio_close.errcheck = check_rktio_ok_t
def rktio_close(rktio: rktio_p, fd: rktio_fd_p):
  """Can report `RKTIO_ERROR_EXISTS` in place of system error,
  and can report `RKTIO_ERROR_UNSUPPORTED_TEXT_MODE` on Windows.
  See also `rktio_write` and `rktio_poll_write_flushed`."""
  # with rktio__fd_lock():
  #   if not rktio__fd_closed(fd):
  #     ret = capi_call("capi_rktio_close", check_rktio_p(rktio), check_rktio_fd_p(fd))
  #     res = check_rktio_ok_t(ret)
  #     rktio__fd_on_close(fd)
  #     return res
  if rktio and fd:
    if ok(self := detach(fd, RktioFd)):
      fd = self
    ret = capi_call("capi_rktio_close", check_rktio_p(rktio), check_rktio_fd_p(fd))
    rktio__fd_on_close(fd)
    return ret


#RKTIO_EXTERN void rktio_close_noerr(rktio_t *rktio, rktio_fd_t *fd);
#/* The same as `rktio_close`, but without reporting errors. There's
#   often nothing good to do if a close fails, epsecially if the close
#   is in the service of handling another failure where you don't want
#   the error code replaced. */
capi_rktio_close_noerr = librktio.rktio_close_noerr
capi_rktio_close_noerr.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_close_noerr.restype = None
def rktio_close_noerr(rktio: rktio_p, fd: rktio_fd_p):
  """The same as `rktio_close`, but without reporting errors. There's
  often nothing good to do if a close fails, epsecially if the close
  is in the service of handling another failure where you don't want
  the error code replaced."""
  with rktio__fd_lock():
    if not rktio__fd_closed(fd):
      capi_call("capi_rktio_close_noerr", check_rktio_p(rktio), check_rktio_fd_p(fd))
      rktio__fd_on_close(fd)

#RKTIO_EXTERN rktio_fd_t *rktio_dup(rktio_t *rktio, rktio_fd_t *rfd);
#/* Copies a file descriptor, where each must be closed or forgotten
#   independenty. */
capi_rktio_dup = librktio.rktio_dup
capi_rktio_dup.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_dup.restype = rktio_fd_p
capi_rktio_dup.errcheck = check_rktio_ok_t
def rktio_dup(rktio, rfd):
  out = capi_call("rktio_dup", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return RktioFd(rktio, out)

#RKTIO_EXTERN void rktio_forget(rktio_t *rktio, rktio_fd_t *fd);
#/* Deallocates a `rktio_fd_t` without closing the file descriptor,
#   but the descriptor is no longer recorded if it was opened with
#   `RKTIO_OPEN_OWN`. */
capi_rktio_forget = librktio.rktio_forget
capi_rktio_forget.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_forget.restype = None
def rktio_forget(rktio, fd):
  """Deallocates a `rktio_fd_t` without closing the file descriptor,
  but the descriptor is no longer recorded if it was opened with
  `RKTIO_OPEN_OWN`."""
  if ok(self := detach(fd, RktioFd)):
    fd = self
  out = capi_call("rktio_forget", check_rktio_p(rktio), check_rktio_fd_p(fd))
  return out

#RKTIO_EXTERN rktio_fd_t *rktio_std_fd(rktio_t *rktio, int which);
#/* Gets stdin/stdout/stderr. */
#/* `which` values: */
##define RKTIO_STDIN  0
##define RKTIO_STDOUT 1
##define RKTIO_STDERR 2
class RKTIO_STD_FD(_enum.IntEnum):
  RKTIO_STDIN  = 0
  RKTIO_STDOUT = 1
  RKTIO_STDERR = 2

RKTIO_STDIN  = RKTIO_STD_FD.RKTIO_STDIN  
RKTIO_STDOUT = RKTIO_STD_FD.RKTIO_STDOUT 
RKTIO_STDERR = RKTIO_STD_FD.RKTIO_STDERR 

capi_rktio_std_fd = librktio.rktio_std_fd
capi_rktio_std_fd.argtypes = [rktio_p, int_t]
capi_rktio_std_fd.restype = rktio_fd_p
capi_rktio_std_fd.errcheck = check_rktio_fd_p
def rktio_std_fd(rktio: rktio_p, which: RKTIO_STD_FD):
  """Gets stdin/stdout/stderr."""
  which = int(RKTIO_STD_FD(which))
  with rktio__fd_lock():
    fd = capi_call("capi_rktio_std_fd", check_rktio_p(rktio), which)
    return rktio__fd_on_new(rktio, fd)


#RKTIO_EXTERN void rktio_create_console(void);
#/* On Windows, ensures that a console is available for output. If a
#   console is created for an application started in GUI mode, The
#   console cannot be closed by the user until the process exits, and
#   then an atexit callback pauses the exit until the user closes the
#   console. */

#RKTIO_EXTERN_ERR(RKTIO_READ_ERROR)
#intptr_t rktio_read(rktio_t *rktio, rktio_fd_t *fd, char *buffer, intptr_t len);
#/* Returns the number of bytes read, possibly 0, in non-blocking mode.
#   Alternatively, the result can be `RKTIO_READ_EOF` for end-of-file
#   or `RKTIO_READ_ERROR` for an error. Although rktio_read is intended
#   to have no buffering, text-mode conversion (on Windows) and certain
#   uncooperative OS corners can buffer 1 byte. */

##define RKTIO_READ_EOF   (-1)
##define RKTIO_READ_ERROR (-2)

class RKTIO_READ_RESULT(_enum.IntEnum):
  RKTIO_READ_EOF = -1
  RKTIO_READ_ERROR = -2
RKTIO_READ_EOF = RKTIO_READ_RESULT.RKTIO_READ_EOF
RKTIO_READ_ERROR = RKTIO_READ_RESULT.RKTIO_READ_ERROR

def check_rktio_read_result(result, *rest):
  check_valid(None, result != RKTIO_READ_ERROR, *rest)
  if result != RKTIO_READ_EOF:
    return result

#RKTIO_EXTERN_ERR(RKTIO_READ_ERROR)
#intptr_t rktio_read(rktio_t *rktio, rktio_fd_t *fd, char *buffer, intptr_t len);
capi_rktio_read = librktio.rktio_read
capi_rktio_read.argtypes = [rktio_p, rktio_fd_p, void_p, intptr_t]
capi_rktio_read.restype = intptr_t
capi_rktio_read.errcheck = check_rktio_read_result
def rktio_read(rktio, fd, count):
  if count <= 0:
    raise TypeError(f"Expected count > 0, got {count}")
  buffer = (_c.c_char * count)()
  amt = capi_call("capi_rktio_read", check_rktio_p(rktio), check_rktio_fd_p(fd), buffer, count)
  if amt is not None: # not EOF
    result = buffer[0:amt]
    return result

#RKTIO_EXTERN_ERR(RKTIO_WRITE_ERROR)
#intptr_t rktio_write(rktio_t *rktio, rktio_fd_t *fd, const char *buffer, intptr_t len);
#/* Returns the number of bytes written, possibly 0, in non-blocking
#   mode. Alternatively, the result can be `RKTIO_WRITE_ERROR` for an
#   error. Although `rktio_write` is intended to write only bytes that
#   can be fully delivered to the OS, there may be OS limitations that
#   require buffering (e.g., on ancient versions of Windows). Use
#   `rktio_poll_write_flushed` to make sure the data is received by the
#   destination before closing `fd`. */

##define RKTIO_WRITE_ERROR (-2)

class RKTIO_WRITE_RESULT(_enum.IntEnum):
  RKTIO_WRITE_ERROR = -2
RKTIO_WRITE_ERROR = RKTIO_WRITE_RESULT.RKTIO_WRITE_ERROR

def check_rktio_write_result(result, *rest):
  check_valid(None, result != RKTIO_WRITE_ERROR, *rest)
  return result

#RKTIO_EXTERN_ERR(RKTIO_WRITE_ERROR)
#intptr_t rktio_write(rktio_t *rktio, rktio_fd_t *fd, const char *buffer, intptr_t len);
capi_rktio_write = librktio.rktio_write
capi_rktio_write.argtypes = [rktio_p, rktio_fd_p, char_p, intptr_t]
capi_rktio_write.restype = rktio_ok_t
capi_rktio_write.errcheck = check_rktio_write_result
def rktio_write(rktio, fd, buffer):
  """Returns the number of bytes written, possibly 0, in non-blocking
  mode. Alternatively, the result can be `RKTIO_WRITE_ERROR` for an
  error. Although `rktio_write` is intended to write only bytes that
  can be fully delivered to the OS, there may be OS limitations that
  require buffering (e.g., on ancient versions of Windows). Use
  `rktio_poll_write_flushed` to make sure the data is received by the
  destination before closing `fd`."""
  s = asbytes(buffer)
  n = len(s)
  out = capi_call("capi_rktio_write", check_rktio_p(rktio), check_rktio_fd_p(fd), s, n)
  return out

#RKTIO_EXTERN_ERR(RKTIO_READ_ERROR)
#intptr_t rktio_read_converted(rktio_t *rktio, rktio_fd_t *fd, char *buffer, intptr_t len,
#                              char *is_converted);
#/* Like `rktio_read`, but also reports whether each character was
#   originally two characters that were converted to a single newline for
#   text mode. */

#RKTIO_EXTERN_ERR(RKTIO_READ_ERROR)
#intptr_t rktio_read_in(rktio_t *rktio, rktio_fd_t *fd, char *buffer, intptr_t start, intptr_t end);
#RKTIO_EXTERN_ERR(RKTIO_WRITE_ERROR)
#intptr_t rktio_write_in(rktio_t *rktio, rktio_fd_t *fd, const char *buffer, intptr_t start, intptr_t end);
#RKTIO_EXTERN_ERR(RKTIO_READ_ERROR)
#intptr_t rktio_read_converted_in(rktio_t *rktio, rktio_fd_t *fd, char *buffer, intptr_t start, intptr_t len,
#                                 char *is_converted, intptr_t converted_start);
#/* Like `rktio_read`, `rktio_write`, and `rktio_read_converted` but
#   accepting start and end positions within `buffer`. */

#RKTIO_EXTERN_NOERR intptr_t rktio_buffered_byte_count(rktio_t *rktio, rktio_fd_t *fd);
#/* Reports the number of bytes that are buffered from the file descriptor.
#   The result is normally zero, but text-mode conversion and the rare
#   uncooperative corner of an OS can make the result 1 byte. */

#/* Each polling function returns one of the following: */
##define RKTIO_POLL_NOT_READY 0
##define RKTIO_POLL_READY 1
##define RKTIO_POLL_ERROR (-2)
class RKTIO_POLL_RESULT(_enum.IntEnum):
  RKTIO_POLL_NOT_READY = 0
  RKTIO_POLL_READY = 1
  RKTIO_POLL_ERROR = -2
RKTIO_POLL_NOT_READY = RKTIO_POLL_RESULT.RKTIO_POLL_NOT_READY
RKTIO_POLL_READY = RKTIO_POLL_RESULT.RKTIO_POLL_READY
RKTIO_POLL_ERROR = RKTIO_POLL_RESULT.RKTIO_POLL_ERROR

def check_rktio_poll_result(code, *rest):
  res = RKTIO_POLL_RESULT(code)
  if res == RKTIO_POLL_ERROR:
    rktio_error(code, *rest)
  return res

#RKTIO_EXTERN_ERR(RKTIO_POLL_ERROR)
#rktio_tri_t rktio_poll_read_ready(rktio_t *rktio, rktio_fd_t *rfd);
capi_rktio_poll_read_ready = librktio.rktio_poll_read_ready
capi_rktio_poll_read_ready.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_poll_read_ready.restype = rktio_ok_t
capi_rktio_poll_read_ready.errcheck = check_rktio_poll_result
def rktio_poll_read_ready(rktio, rfd):
  out = capi_call("rktio_poll_read_ready", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out
#RKTIO_EXTERN_ERR(RKTIO_POLL_ERROR)
#rktio_tri_t rktio_poll_write_ready(rktio_t *rktio, rktio_fd_t *rfd);
capi_rktio_poll_write_ready = librktio.rktio_poll_write_ready
capi_rktio_poll_write_ready.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_poll_write_ready.restype = rktio_ok_t
capi_rktio_poll_write_ready.errcheck = check_rktio_poll_result
def rktio_poll_write_ready(rktio, rfd):
  out = capi_call("rktio_poll_write_ready", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

#RKTIO_EXTERN_ERR(RKTIO_POLL_ERROR)
#rktio_tri_t rktio_poll_write_flushed(rktio_t *rktio, rktio_fd_t *rfd);
#/* See `rktio_write` above. Currently, the result is `RKTIO_POLL_NO_READY`
#   only on Windows, and only for a pipe or similar non-regular file.
#   A pipe counts as "flushed" when the other end has received the data
#   (because the sent data doesn't persist beyond closing the pipe). */
capi_rktio_poll_write_flushed = librktio.rktio_poll_write_flushed
capi_rktio_poll_write_flushed.argtypes = [rktio_p]
capi_rktio_poll_write_flushed.restype = int_t
capi_rktio_poll_write_flushed.errcheck = check_rktio_poll_result
def rktio_poll_write_flushed(rktio, rfd):
  """See `rktio_write` above. Currently, the result is `RKTIO_POLL_NO_READY`
  only on Windows, and only for a pipe or similar non-regular file.
  A pipe counts as "flushed" when the other end has received the data
  (because the sent data doesn't persist beyond closing the pipe)."""
  out = capi_call("rktio_poll_write_flushed", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out

#RKTIO_EXTERN_ERR(RKTIO_LOCK_ERROR)
#rktio_tri_t rktio_file_lock_try(rktio_t *rktio, rktio_fd_t *rfd, rktio_bool_t excl);
#RKTIO_EXTERN rktio_ok_t rktio_file_unlock(rktio_t *rktio, rktio_fd_t *rfd);
#/* Advisory file locks, where `excl` attempts to claim an exclusive
#   lock. Whether these work in various situations depend on many OS
#   details, where the differences involve promoting from non-exlcusive
#   to exclusive, taking a lock that is already held, getting an
#   exclusive lock for a file descriptor in read mode, getting a
#   non-exclusive lock in write mode, and whether a lock prevents
#   opening or using another file descriptor. */

##define RKTIO_LOCK_ERROR        (-2)
##define RKTIO_LOCK_ACQUIRED     1
##define RKTIO_LOCK_NOT_ACQUIRED 0

#typedef rktio_int64_t rktio_filesize_t;
rktio_filesize_t = rktio_int64_t
rktio_filesize_p = _c.POINTER(rktio_filesize_t)

def out_rktio_filesize(ptr, *rest):
  return out_rktio_value(ptr, rktio_filesize_p, *rest)

#RKTIO_EXTERN rktio_ok_t rktio_set_file_position(rktio_t *rktio, rktio_fd_t *rfd, rktio_filesize_t pos, int whence);
capi_rktio_set_file_position = librktio.rktio_set_file_position
capi_rktio_set_file_position.argtypes = [rktio_p, rktio_fd_p, rktio_filesize_t, int_t]
capi_rktio_set_file_position.restype = rktio_ok_t
capi_rktio_set_file_position.errcheck = check_rktio_ok_t
#/* Can report `RKTIO_ERROR_CANNOT_FILE_POSITION` on Windows. */
#/* For `whence`: */
#enum {
#  RKTIO_POSITION_FROM_START,
#  RKTIO_POSITION_FROM_END
#};
class RKTIO_POSITION(_enum.IntEnum):
  RKTIO_POSITION_FROM_START = 0
  RKTIO_POSITION_FROM_END = 1
RKTIO_POSITION_FROM_START = RKTIO_POSITION.RKTIO_POSITION_FROM_START
RKTIO_POSITION_FROM_END = RKTIO_POSITION.RKTIO_POSITION_FROM_END
def rktio_set_file_position(rktio: rktio_p, rfd: rktio_fd_p, pos: int, whence: int = RKTIO_POSITION_FROM_START):
  return capi_call("rktio_set_file_position", check_rktio_p(rktio), check_rktio_fd_p(rfd), rktio_filesize_t(pos), int_t(whence))


#RKTIO_EXTERN rktio_filesize_t *rktio_get_file_position(rktio_t *rktio, rktio_fd_t *rfd);
#/* Returns the file position, not taking into account rare input
#   buffering (see `rktio_read`). On Windows, can report
#   `RKTIO_ERROR_CANNOT_FILE_POSITION`, which doesn't have a
#   corresponding Windows error code. */
capi_rktio_get_file_position = librktio.rktio_get_file_position
capi_rktio_get_file_position.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_get_file_position.restype = rktio_filesize_p
capi_rktio_get_file_position.errcheck = out_rktio_filesize
def rktio_get_file_position(rktio: rktio_p, fd: rktio_fd_p):
  """Returns the file position, not taking into account rare input
  buffering (see `rktio_read`). On Windows, can report
  `RKTIO_ERROR_CANNOT_FILE_POSITION`, which doesn't have a
  corresponding Windows error code."""
  return capi_call("rktio_get_file_position", check_rktio_p(rktio), check_rktio_fd_p(fd))

#RKTIO_EXTERN rktio_ok_t rktio_set_file_size(rktio_t *rktio, rktio_fd_t *rfd, rktio_filesize_t sz);
#/* Can report `RKTIO_ERROR_CANNOT_FILE_POSITION` on Windows. */

#typedef struct rktio_fd_transfer_t rktio_fd_transfer_t;
#/* Represents an rktio_fd_t that is detached from a specific rktio_t */

#RKTIO_EXTERN_NOERR rktio_fd_transfer_t *rktio_fd_detach(rktio_t *rktio, rktio_fd_t *rfd);
#/* Returns a variant of `rfd` that does not depend on `rktio`. The
#   `rfd` must not currently have any file locks, and deatching
#   transfers ownership of `rfd` to the result. To use the result, it
#   must be reattached to some `rktio_t` using rktio_fd_attach, or it
#   can be freed with `rktio_fd_free_transfer`. */

#RKTIO_EXTERN_NOERR rktio_fd_t *rktio_fd_attach(rktio_t *rktio, rktio_fd_transfer_t *rfdt);
#/* Attaches a file descriptor that was formerly detached with
#   `rktio_fd_detach` so it can be used again, consuming the `rfdt`. */

#RKTIO_EXTERN void rktio_fd_close_transfer(rktio_fd_transfer_t *rfdt);
#/* Closes and frees a detached file descriptor without having to
#   attach it to a `rktio_t`. */

#/*************************************************/
#/* Pipes                                         */

#RKTIO_EXTERN rktio_fd_t **rktio_make_pipe(rktio_t *rktio, int flags);
#/* Makes a pair of file descriptors for a pipe. The first one
#   is the read end, and the second is the write end. The `flags`
#   can declare the intended sharing of the file descriptors
#   with a child process, and is useful only on Windows. */
#/* For `flags`: */
##define RKTIO_NO_INHERIT_INPUT  (1<<0)
##define RKTIO_NO_INHERIT_OUTPUT (1<<1)
class RKTIO_NO_INHERIT(_enum.IntFlag):
  RKTIO_NO_INHERIT_INPUT = _enum.auto()
  RKTIO_NO_INHERIT_OUTPUT = _enum.auto()
RKTIO_NO_INHERIT_INPUT = RKTIO_NO_INHERIT.RKTIO_NO_INHERIT_INPUT
RKTIO_NO_INHERIT_OUTPUT = RKTIO_NO_INHERIT.RKTIO_NO_INHERIT_OUTPUT

# /* Internal variant for use by rktio_process: */
# int rktio_make_os_pipe(rktio_t *rktio, intptr_t *a, int flags)
capi_rktio_make_os_pipe = librktio.rktio_make_os_pipe
capi_rktio_make_os_pipe.argtypes = [rktio_p, intptr_t * 2, int_t]
capi_rktio_make_os_pipe.restype = rktio_ok_t
def rktio_make_os_pipe(rktio, flags: RKTIO_NO_INHERIT = 0):
  fds = (intptr_t * 2)()
  ret = capi_call("rktio_make_os_pipe", check_rktio_p(rktio), fds, int_t(RKTIO_NO_INHERIT(flags)))
  check_valid(rktio, ret == 0)
  # if ret > 0:
  #   return None
  return fds[0], fds[1]

##RKTIO_EXTERN rktio_fd_t **rktio_make_pipe(rktio_t *rktio, int flags);
#capi_rktio_make_pipe = librktio.rktio_make_pipe
#capi_rktio_make_pipe.argtypes = [rktio_p, int_t]
#capi_rktio_make_pipe.restype = _c.POINTER(rktio_fd_p)
##capi_rktio_make_pipe.restype = (rktio_fd_p * 2)
#capi_rktio_make_pipe.errcheck = check_rktio_ok_t
#def rktio_make_pipe(rktio, flags=RKTIO_NO_INHERIT_INPUT):
#  """Makes a pair of file descriptors for a pipe. The first one
#  is the read end, and the second is the write end. The `flags`
#  can declare the intended sharing of the file descriptors
#  with a child process, and is useful only on Windows."""
#  ptr = capi_call("capi_rktio_make_pipe", check_rktio_p(rktio), int_t(RKTIO_NO_INHERIT(flags)))
#  try:
#    # i = RktioFd(rktio, ptr[0], close=False)
#    # o = RktioFd(rktio, ptr[1], close=False)
#    i = ptr[0]
#    o = ptr[1]
#    #del ptr
#    return i, o
#  finally:
#    #rktio_free(ptr)
#    pass

def rktio_make_pipe(rktio, flags=RKTIO_NO_INHERIT_INPUT):
  """Makes a pair of file descriptors for a pipe. The first one
  is the read end, and the second is the write end. The `flags`
  can declare the intended sharing of the file descriptors
  with a child process, and is useful only on Windows."""
  fds = rktio_make_os_pipe(rktio, flags)
  i = rktio_system_fd(rktio, fds[0], RKTIO_OPEN_READ | RKTIO_OPEN_NOT_REGFILE)
  o = rktio_system_fd(rktio, fds[1], RKTIO_OPEN_WRITE | RKTIO_OPEN_NOT_REGFILE)
  return i, o


#/*************************************************/
#/* Network                                       */

#typedef struct rktio_addrinfo_lookup_t rktio_addrinfo_lookup_t;
#typedef struct rktio_addrinfo_t rktio_addrinfo_t;

class rktio_addrinfo_lookup_t(_c.Structure):
  pass

rktio_addrinfo_lookup_p = _c.POINTER(rktio_addrinfo_lookup_t)

def check_rktio_addrinfo_lookup_p(p, *args):
  return check_type(p, rktio_addrinfo_lookup_p, "rktio_addrinfo_lookup_p")

def check_rktio_addrinfo_lookup_p_or_null(p, *args):
  return check_type_or_null(p, rktio_addrinfo_lookup_p, "rktio_addrinfo_lookup_p")


class rktio_addrinfo_t(_c.Structure):
  pass

rktio_addrinfo_p = _c.POINTER(rktio_addrinfo_t)

def check_rktio_addrinfo_p(p, *args):
  return check_type(p, rktio_addrinfo_p, "rktio_addrinfo_p")

def check_rktio_addrinfo_p_or_null(p, *args):
  return check_type_or_null(p, rktio_addrinfo_p, "rktio_addrinfo_p")


class RktioAddrinfo(CParameter):
  def __init__(self, rktio, p):
    typecheck_or_null(p, rktio_addrinfo_p, "rktio_addrinfo_p")
    super().__init__(p)
    self._rktio = check_rktio_p(rktio)

  def unset(self):
    super().unset()
    self._rktio = None

  def __bool__(self):
    if not self._rktio:
      return False
    return super().__bool__()

  def dispose(self):
    if self:
      rktio_addrinfo_free(self._rktio, self)
    super().dispose()



#RKTIO_EXTERN rktio_addrinfo_lookup_t *rktio_start_addrinfo_lookup(rktio_t *rktio,
#                                                                  rktio_const_string_t hostname, int portno,
#                                                                  int family, rktio_bool_t passive, rktio_bool_t tcp);
#/* The `family` argument should be one of the following: */
##define RKTIO_FAMILY_ANY (-1)
class RKTIO_FAMILY(_enum.IntEnum):
  RKTIO_FAMILY_ANY = -1
RKTIO_FAMILY_ANY = RKTIO_FAMILY.RKTIO_FAMILY_ANY
capi_rktio_start_addrinfo_lookup = librktio.rktio_start_addrinfo_lookup
capi_rktio_start_addrinfo_lookup.argtypes = [rktio_p, char_p, int_t, int_t, rktio_bool_t, rktio_bool_t]
capi_rktio_start_addrinfo_lookup.restype = rktio_addrinfo_lookup_p
capi_rktio_start_addrinfo_lookup.errcheck = check_rktio_ok_t
def rktio_start_addrinfo_lookup(rktio, hostname: Optional[str], portno: int, family: int, passive: bool, tcp: bool):
  out = capi_call("rktio_start_addrinfo_lookup", check_rktio_p(rktio), asbytes(hostname), check_int(portno), check_int(family), check_int(passive), check_int(tcp))
  return out

#RKTIO_EXTERN_NOERR int rktio_get_ipv4_family(rktio_t *rktio);
capi_rktio_get_ipv4_family = librktio.rktio_get_ipv4_family
capi_rktio_get_ipv4_family.argtypes = [rktio_p]
capi_rktio_get_ipv4_family.restype = int_t
def rktio_get_ipv4_family(rktio):
  out = capi_call("rktio_get_ipv4_family", check_rktio_p(rktio))
  return out

#RKTIO_EXTERN_ERR(RKTIO_POLL_ERROR)
#rktio_tri_t rktio_poll_addrinfo_lookup_ready(rktio_t *rktio, rktio_addrinfo_lookup_t *lookup);
#/* Check whether an address is available for a lookup request. */
capi_rktio_poll_addrinfo_lookup_ready = librktio.rktio_poll_addrinfo_lookup_ready
capi_rktio_poll_addrinfo_lookup_ready.argtypes = [rktio_p, rktio_addrinfo_lookup_p]
capi_rktio_poll_addrinfo_lookup_ready.restype = rktio_ok_t
capi_rktio_poll_addrinfo_lookup_ready.errcheck = check_rktio_poll_result
def rktio_poll_addrinfo_lookup_ready(rktio, lookup):
  """Check whether an address is available for a lookup request."""
  out = capi_call("rktio_poll_addrinfo_lookup_ready", check_rktio_p(rktio), check_rktio_addrinfo_lookup_p(lookup))
  return out

#RKTIO_EXTERN rktio_addrinfo_t *rktio_addrinfo_lookup_get(rktio_t *rktio, rktio_addrinfo_lookup_t *lookup);
#/* Deallocates `lookup`. */
capi_rktio_addrinfo_lookup_get = librktio.rktio_addrinfo_lookup_get
capi_rktio_addrinfo_lookup_get.argtypes = [rktio_p, rktio_addrinfo_lookup_p]
capi_rktio_addrinfo_lookup_get.restype = rktio_addrinfo_p
capi_rktio_addrinfo_lookup_get.errcheck = check_rktio_ok_t
def rktio_addrinfo_lookup_get(rktio, lookup):
  if ok(out := capi_call("rktio_addrinfo_lookup_get", check_rktio_p(rktio), check_rktio_addrinfo_lookup_p(lookup))):
    return RktioAddrinfo(rktio, out)

#RKTIO_EXTERN void rktio_addrinfo_lookup_stop(rktio_t *rktio, rktio_addrinfo_lookup_t *lookup);
#/* Abandons a lookup whose result (or error) is not yet received. */
capi_rktio_addrinfo_lookup_stop = librktio.rktio_addrinfo_lookup_stop
capi_rktio_addrinfo_lookup_stop.argtypes = [rktio_p, rktio_addrinfo_lookup_p]
capi_rktio_addrinfo_lookup_stop.restype = None
def rktio_addrinfo_lookup_stop(rktio, lookup):
  """Abandons a lookup whose result (or error) is not yet received."""
  out = capi_call("rktio_addrinfo_lookup_stop", check_rktio_p(rktio), check_rktio_addrinfo_lookup_p(lookup))
  return out

#RKTIO_EXTERN void rktio_addrinfo_free(rktio_t *rktio, rktio_addrinfo_t *a);
#/* Frees the result of a lookup. */
capi_rktio_addrinfo_free = librktio.rktio_addrinfo_free
capi_rktio_addrinfo_free.argtypes = [rktio_p, rktio_addrinfo_p]
capi_rktio_addrinfo_free.restype = None
def rktio_addrinfo_free(rktio, addrinfo):
  """Frees the result of a lookup."""
  if ok(self := detach(addrinfo, RktioAddrinfo)):
    addrinfo = self
  out = capi_call("rktio_addrinfo_free", check_rktio_p(rktio), check_rktio_addrinfo_p(addrinfo))
  return out

#typedef struct rktio_listener_t rktio_listener_t;
#typedef struct rktio_connect_t rktio_connect_t;

rktio_socket_t = intptr_t

#class rktio_listener_t(_c.Structure):
#  _fields_ = [
#      ("count", int_t),
#  ]

#  def __len__(self):
#    return self.count

#  def ext(self):
#    cls = rktio_listener_n(len(self))
#    #return cls.from_address(_c.addressof(self))
#    return _c.cast(_c.addressof(self), _c.POINTER(cls))


def dynamic_array(cls, address, count):
  cls = (cls * count)
  out = cls.from_address(address)
  return out

class rktio_listener_t(_c.Structure):
  _fields_ = [
      ("count", int_t),
      #("s", _c.POINTER(rktio_socket_t)),
      ("s_", (rktio_socket_t * 0)),
      ]

  def __hash__(self):
    return hash(id(self))
  
  @functools.lru_cache
  def sockets(self, count):
    return dynamic_array(rktio_socket_t, _c.addressof(self.s_), count)

  # @property
  # def s(self):
  #   n = len(self)
  #   cls = (rktio_socket_t * n)
  #   out = cls.from_address(_c.addressof(self.s_))
  #   return out
  @property
  def s(self):
    return self.sockets(len(self))

  def __len__(self):
    return self.count

  def __getitem__(self, i):
    return self.s[i]
    # if i >= 0 and i < len(self):
    #   return self.s[i]
    # raise IndexError(i)

  def __setitem__(self, i, s):
    self.s[i] = s
    # if isinstance(i, slice):
    #   n = len(self)
    #   start, stop, step = i.indices(n)
    #   if not (0 <= start < n):
    #     raise IndexError(i)
    #   if not (0 <= stop <= n):
    #     raise IndexError(i)
    #   for idx in range(start, stop, step):
    #     self.s[idx] = s[idx]
    # else:
    #   if i >= 0 and i < len(self):
    #     self.s[i] = s
    #     return
    #   raise IndexError(i)

import functools

@functools.lru_cache
def rktio_listener_n(count):
  class rktio_listener_ext_t(rktio_listener_t):
    _fields_ = [
        #("count", int_t),
        ("s", (rktio_socket_t * count))
        ]

    def __getitem__(self, i):
      if i >= 0 and i < len(self):
        return self.s[i]
      raise IndexError(i)

    def __setitem__(self, i, s):
      if isinstance(i, slice):
        n = len(self)
        start, stop, step = i.indices(n)
        if not (0 <= start < n):
          raise IndexError(i)
        if not (0 <= stop <= n):
          raise IndexError(i)
        for idx in range(start, stop, step):
          self.s[idx] = s[idx]
      else:
        if i >= 0 and i < len(self):
          self.s[i] = s
          return
        raise IndexError(i)
  return rktio_listener_ext_t

rktio_listener_p = _c.POINTER(rktio_listener_t)

def check_rktio_listener_p(p, *args):
  return check_type(p, rktio_listener_p, "rktio_listener_p")

def check_rktio_listener_p_or_null(p, *args):
  return check_type_or_null(p, rktio_listener_p, "rktio_listener_p")


def rktio_listener_alloc(*fds):
  n = len(fds)
  cls = rktio_listener_n(n)
  l = cls()
  l.count = n
  #l.s = (rktio_socket_t * n)()
  l[:] = fds
  return _c.pointer(l)



#RKTIO_EXTERN rktio_listener_t *rktio_listen(rktio_t *rktio, rktio_addrinfo_t *local, int backlog, rktio_bool_t reuse);
#/* Can fail with `RKTIO_ERROR_TRY_AGAIN_WITH_IPV4`, which suggests
#   trying an address using the family reported by
#   `rktio_get_ipv4_family` instead of `RKTIO_FAMILY_ANY`. */
capi_rktio_listen = librktio.rktio_listen
capi_rktio_listen.argtypes = [rktio_p, rktio_addrinfo_p, int_t, rktio_bool_t]
capi_rktio_listen.restype = rktio_listener_p
capi_rktio_listen.errcheck = check_rktio_ok_t
def rktio_listen(rktio, addrinfo, backlog: int, reuse: bool):
  """
  #/* Can fail with `RKTIO_ERROR_TRY_AGAIN_WITH_IPV4`, which suggests
  #   trying an address using the family reported by
  #   `rktio_get_ipv4_family` instead of `RKTIO_FAMILY_ANY`. */
  """
  out = capi_call("rktio_listen", check_rktio_p(rktio), check_rktio_addrinfo_p(addrinfo), check_int(backlog), check_int(reuse))
  return out

#RKTIO_EXTERN void rktio_listen_stop(rktio_t *rktio, rktio_listener_t *l);
#/* Stops a listener. */
capi_rktio_listen_stop = librktio.rktio_listen_stop
capi_rktio_listen_stop.argtypes = [rktio_p, rktio_listener_p]
capi_rktio_listen_stop.restype = None
def rktio_listen_stop(rktio, l):
  """Stops a listener."""
  out = capi_call("rktio_listen_stop", check_rktio_p(rktio), check_rktio_listener_p(l))
  return out

#RKTIO_EXTERN_ERR(RKTIO_POLL_ERROR)
#rktio_tri_t rktio_poll_accept_ready(rktio_t *rktio, rktio_listener_t *listener);
#/* Returns one of `RKTIO_POLL_READY`, etc. */
capi_rktio_poll_accept_ready = librktio.rktio_poll_accept_ready
capi_rktio_poll_accept_ready.argtypes = [rktio_p, rktio_listener_p]
capi_rktio_poll_accept_ready.restype = rktio_ok_t
capi_rktio_poll_accept_ready.errcheck = check_rktio_poll_result
def rktio_poll_accept_ready(rktio, l):
  out = capi_call("rktio_poll_accept_ready", check_rktio_p(rktio), check_rktio_listener_p(l))
  return out

#RKTIO_EXTERN rktio_fd_t *rktio_accept(rktio_t *rktio, rktio_listener_t *listener);
#/* Accepts one connection on a listener. */
capi_rktio_accept = librktio.rktio_accept
capi_rktio_accept.argtypes = [rktio_p, rktio_listener_p]
capi_rktio_accept.restype = rktio_fd_p
capi_rktio_accept.errcheck = check_rktio_ok_t
def rktio_accept(rktio, l):
  """Accepts one connection on a listener."""
  out = capi_call("rktio_accept", check_rktio_p(rktio), check_rktio_listener_p(l))
  return out

#RKTIO_EXTERN rktio_connect_t *rktio_start_connect(rktio_t *rktio,
#                                                  rktio_addrinfo_t *remote,
#                                                  RKTIO_NULLABLE rktio_addrinfo_t *local);
#/* Starts a connection request. Addreses must not be freed until the
#   connection is complete, errored, or stopped. */

#RKTIO_EXTERN rktio_fd_t *rktio_connect_finish(rktio_t *rktio, rktio_connect_t *conn);
#/* A `RKTIO_ERROR_CONNECT_TRYING_NEXT` error effectively means "try
#   again", and the connection object is still valid. On any other
#   error, or if the connection completes successfully, `conn` is
#   deallocated */

#RKTIO_EXTERN void rktio_connect_stop(rktio_t *rktio, rktio_connect_t *conn);
#/* Stops a connection whose result or error has not been received. */

#RKTIO_EXTERN_ERR(RKTIO_POLL_ERROR)
#rktio_tri_t rktio_poll_connect_ready(rktio_t *rktio, rktio_connect_t *conn);
#/* Returns one of `RKTIO_POLL_READY`, etc. */

#RKTIO_EXTERN rktio_fd_t *rktio_connect_trying(rktio_t *rktio, rktio_connect_t *conn);
#/* Returns a file descriptor that `conn` is currently trying, or
#   returns NULL without setting any error. The result file descriptor
#   should not be closed, and may be closed by a `rktio_connect_finish`
#   or `rktio_connect_stop` call (so if you register it in an long-term
#   poll set, unregister it before trying to finish or stop the
#   connection). */

#RKTIO_EXTERN rktio_ok_t rktio_socket_shutdown(rktio_t *rktio, rktio_fd_t *rfd, int mode);
#/* Useful for TCP to report an EOF to the other end. Does not close the socket,
#   but may make it ineligible for forther use.
#   `mode` values: */
##define RKTIO_SHUTDOWN_READ   0
##define RKTIO_SHUTDOWN_WRITE  1

#RKTIO_EXTERN rktio_fd_t *rktio_udp_open(rktio_t *rktio, RKTIO_NULLABLE rktio_addrinfo_t *addr, int family);
#/* The `addr` argument can be NULL to create a socket without
#   specifying an interface, and `family` is used only if `addr` is not
#   specified. */
capi_rktio_udp_open = librktio.rktio_udp_open
capi_rktio_udp_open.argtypes = [rktio_p, rktio_addrinfo_p, int_t]
capi_rktio_udp_open.restype = rktio_fd_p
capi_rktio_udp_open.errcheck = check_rktio_ok_t
def rktio_udp_open(rktio, addr, family: int):
  """The `addr` argument can be NULL to create a socket without
  specifying an interface, and `family` is used only if `addr` is not
  specified."""
  out = capi_call("rktio_udp_open", check_rktio_p(rktio), check_rktio_addrinfo_p_or_null(addr), family)
  return out

#RKTIO_EXTERN rktio_ok_t rktio_udp_disconnect(rktio_t *rktio, rktio_fd_t *rfd);
#RKTIO_EXTERN rktio_ok_t rktio_udp_bind(rktio_t *rktio, rktio_fd_t *rfd, rktio_addrinfo_t *addr,
#                                       rktio_bool_t reuse);
#RKTIO_EXTERN rktio_ok_t rktio_udp_connect(rktio_t *rktio, rktio_fd_t *rfd, rktio_addrinfo_t *addr);

#RKTIO_EXTERN_ERR(RKTIO_WRITE_ERROR)
#intptr_t rktio_udp_sendto(rktio_t *rktio, rktio_fd_t *rfd, RKTIO_NULLABLE rktio_addrinfo_t *addr,
#                          const char *buffer, intptr_t len);
#/* Extends `rktio_write` to accept a destination `addr`, and binds `rfd` if it 
#   is not bound already. The `addr` can be NULL if the socket is connected. */

#RKTIO_EXTERN_ERR(RKTIO_WRITE_ERROR)
#intptr_t rktio_udp_sendto_in(rktio_t *rktio, rktio_fd_t *rfd, RKTIO_NULLABLE rktio_addrinfo_t *addr,
#                             const char *buffer, intptr_t start, intptr_t end);
#/* Like `rktio_udp_sendto`, but with starting and ending offsets within `buffer`. */

#typedef struct rktio_length_and_addrinfo_t {
#  intptr_t len;
#  char **address; /* like the result of `rktio_socket_address` */
#} rktio_length_and_addrinfo_t;

#RKTIO_EXTERN rktio_length_and_addrinfo_t *rktio_udp_recvfrom(rktio_t *rktio, rktio_fd_t *rfd,
#                                                             char *buffer, intptr_t len);
#/* Extend `rktio_read` to report the sender. If the reported error can
#   be `RKTIO_ERROR_TRY_AGAIN` or `RKTIO_ERROR_INFO_TRY_AGAIN`, where
#   the latter can happen if the sock claims to be ready to read. */

#RKTIO_EXTERN rktio_length_and_addrinfo_t *rktio_udp_recvfrom_in(rktio_t *rktio, rktio_fd_t *rfd,
#                                                                char *buffer, intptr_t start, intptr_t end);
#/* Like `rktio_udp_recvfrom`, but with starting and ending offsets. */

#RKTIO_EXTERN rktio_ok_t rktio_udp_set_receive_buffer_size(rktio_t *rktio, rktio_fd_t *rfd, int size);

#RKTIO_EXTERN rktio_ok_t rktio_udp_set_ttl(rktio_t *rktio, rktio_fd_t *rfd, int ttl_val);
#RKTIO_EXTERN_ERR(RKTIO_PROP_ERROR) rktio_tri_t rktio_udp_get_ttl(rktio_t *rktio, rktio_fd_t *rfd);


#RKTIO_EXTERN_ERR(RKTIO_PROP_ERROR) rktio_tri_t rktio_udp_get_multicast_loopback(rktio_t *rktio, rktio_fd_t *rfd);
#RKTIO_EXTERN rktio_ok_t rktio_udp_set_multicast_loopback(rktio_t *rktio, rktio_fd_t *rfd, rktio_bool_t on);
#RKTIO_EXTERN_ERR(RKTIO_PROP_ERROR) rktio_tri_t rktio_udp_get_multicast_ttl(rktio_t *rktio, rktio_fd_t *rfd);

#RKTIO_EXTERN rktio_ok_t rktio_udp_set_multicast_ttl(rktio_t *rktio, rktio_fd_t *rfd, int ttl_val);

##define RKTIO_PROP_ERROR (-2)

#RKTIO_EXTERN char *rktio_udp_multicast_interface(rktio_t *rktio, rktio_fd_t *rfd);
#RKTIO_EXTERN rktio_ok_t rktio_udp_set_multicast_interface(rktio_t *rktio, rktio_fd_t *rfd,
#                                                          RKTIO_NULLABLE rktio_addrinfo_t *addr);
#/* The `addr` argument can be NULL to auto-select the interface. */

#RKTIO_EXTERN rktio_ok_t rktio_udp_change_multicast_group(rktio_t *rktio, rktio_fd_t *rfd,
#                                                         rktio_addrinfo_t *group_addr,
#                                                         RKTIO_NULLABLE rktio_addrinfo_t *intf_addr,
#                                                         int action);
#/* `action` values: */
#enum {
#  RKTIO_ADD_MEMBERSHIP,
#  RKTIO_DROP_MEMBERSHIP
#};

def check_addr_port_strings(out, *rest):
  if out:
    res = dynamic_array(char_p, out, 2)
    addr = asutf8(res[0])
    port = asutf8(res[1])
    rktio_free(out)
    return addr, port
  else:
    raise ValueError("expected pointer", out)

#RKTIO_EXTERN char **rktio_socket_address(rktio_t *rktio, rktio_fd_t *rfd);
capi_rktio_socket_address = librktio.rktio_socket_address
capi_rktio_socket_address.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_socket_address.restype = void_p
capi_rktio_socket_address.errcheck = check_addr_port_strings
def rktio_socket_address(rktio, rfd):
  out = capi_call("rktio_socket_address", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out
#RKTIO_EXTERN char **rktio_socket_peer_address(rktio_t *rktio, rktio_fd_t *rfd);
capi_rktio_socket_peer_address = librktio.rktio_socket_peer_address
capi_rktio_socket_peer_address.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_socket_peer_address.restype = void_p
capi_rktio_socket_peer_address.errcheck = check_addr_port_strings
def rktio_socket_peer_address(rktio, rfd):
  out = capi_call("rktio_socket_peer_address", check_rktio_p(rktio), check_rktio_fd_p(rfd))
  return out
#RKTIO_EXTERN char **rktio_listener_address(rktio_t *rktio, rktio_listener_t *lnr);
capi_rktio_listener_address = librktio.rktio_listener_address
capi_rktio_listener_address.argtypes = [rktio_p, rktio_listener_p]
capi_rktio_listener_address.restype = void_p
capi_rktio_listener_address.errcheck = check_addr_port_strings
def rktio_listener_address(rktio, lnr):
  out = capi_call("rktio_listener_address", check_rktio_p(rktio), check_rktio_listener_p(lnr))
  return out
#/* These return two strings in an array (where the array itself should
#   be deallocated): address and service. */

#/*************************************************/
#/* Environment variables                         */

#RKTIO_EXTERN rktio_bool_t rktio_is_ok_envvar_name(rktio_t *rktio, rktio_const_string_t name);
#/* Checks whether a string is valid as a new (e.g., no "="). */

#RKTIO_EXTERN rktio_bool_t rktio_are_envvar_names_case_insensitive(rktio_t *rktio);
#/* Checks whether environment variables are case-folded by the OS.
#   That doesn't mean that clients need to case-fold names, but clients
#   may want to imitate the OS. */

#RKTIO_EXTERN char *rktio_getenv(rktio_t *rktio, rktio_const_string_t name);
#/* Gets an environment variable value, or reports
#   `RKTIO_ERROR_NO_SUCH_ENVVAR` when returning NULL; the result must
#   be freed. */
capi_rktio_getenv = librktio.rktio_getenv
capi_rktio_getenv.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_getenv.restype = void_p
capi_rktio_getenv.errcheck = check_bytes
def rktio_getenv(rktio, name):
  """
  Gets an environment variable value, or reports
  `RKTIO_ERROR_NO_SUCH_ENVVAR` when returning NULL
  """
  try:
    if ok(out := capi_call("rktio_getenv", check_rktio_p(rktio), asbytes(name))):
      if isinstance(name, str):
        return asutf8(out)
      return out
  except RktioException as e:
    if e.code != RKTIO_ERROR_NO_SUCH_ENVVAR:
      raise e

#RKTIO_EXTERN rktio_ok_t rktio_setenv(rktio_t *rktio, rktio_const_string_t name, rktio_const_string_t val);
#/* Set an environment variable's value, where a NULL value for `val`
#   unsets it. */
capi_rktio_setenv = librktio.rktio_setenv
capi_rktio_setenv.argtypes = [rktio_p, rktio_const_string_t, rktio_const_string_t]
capi_rktio_setenv.restype = rktio_ok_t
capi_rktio_setenv.errcheck = check_rktio_ok_t
def rktio_setenv(rktio, name, val):
  """Set an environment variable's value, where a NULL value for `val`
  unsets it."""
  return capi_call("rktio_setenv", check_rktio_p(rktio), asbytes(name), asbytes(val))

#typedef struct rktio_envvars_t rktio_envvars_t;

#RKTIO_EXTERN rktio_envvars_t *rktio_envvars(rktio_t *rktio);
#/* Extracts all environment variables into a record */

#RKTIO_EXTERN rktio_envvars_t *rktio_empty_envvars(rktio_t *rktio);
#/* Create an empty environment-variables record. */

#RKTIO_EXTERN rktio_envvars_t *rktio_envvars_copy(rktio_t *rktio, rktio_envvars_t *envvars);
#/* Clones an environment-variable record. */

#RKTIO_EXTERN void rktio_envvars_free(rktio_t *rktio, rktio_envvars_t *envvars);
#/* Deallocates an environment-variables record: */

#RKTIO_EXTERN char *rktio_envvars_get(rktio_t *rktio, rktio_envvars_t *envvars, rktio_const_string_t name);
#RKTIO_EXTERN void rktio_envvars_set(rktio_t *rktio, rktio_envvars_t *envvars, rktio_const_string_t name, rktio_const_string_t value);
#/* Access/update environment-variables record by name. */

#RKTIO_EXTERN_NOERR intptr_t rktio_envvars_count(rktio_t *rktio, rktio_envvars_t *envvars);
#RKTIO_EXTERN char *rktio_envvars_name_ref(rktio_t *rktio, rktio_envvars_t *envvars, intptr_t i);
#RKTIO_EXTERN char *rktio_envvars_value_ref(rktio_t *rktio, rktio_envvars_t *envvars, intptr_t i);
#/* Access/update environment-variables record by index. */

#/*************************************************/
#/* Processes                                     */

#typedef struct rktio_process_t rktio_process_t;

#typedef struct rktio_process_result_t {
#  rktio_process_t *process;
#  rktio_fd_t *stdin_fd;
#  rktio_fd_t *stdout_fd;
#  rktio_fd_t *stderr_fd;
#} rktio_process_result_t;

#RKTIO_EXTERN rktio_process_result_t *rktio_process(rktio_t *rktio,
#                                                   rktio_const_string_t command, int argc, rktio_const_string_t *argv,
#                                                   RKTIO_NULLABLE rktio_fd_t *stdout_fd,
#                                                   RKTIO_NULLABLE rktio_fd_t *stdin_fd,
#                                                   RKTIO_NULLABLE rktio_fd_t *stderr_fd,
#                                                   RKTIO_NULLABLE rktio_process_t *group_proc,
#                                                   rktio_const_string_t current_directory,
#                                                   rktio_envvars_t *envvars,
#                                                   int flags);
#/* The output file descriptors `stdin_fd` must not be a pending-open
#   descriptor. The `flags` are: */
##define RKTIO_PROCESS_NEW_GROUP                 (1<<0)
##define RKTIO_PROCESS_STDOUT_AS_STDERR          (1<<1)
##define RKTIO_PROCESS_WINDOWS_EXACT_CMDLINE     (1<<2)
##define RKTIO_PROCESS_WINDOWS_CHAIN_TERMINATION (1<<3)
##define RKTIO_PROCESS_NO_CLOSE_FDS              (1<<4)
##define RKTIO_PROCESS_NO_INHERIT_FDS            (1<<5)

#RKTIO_EXTERN_NOERR int rktio_process_allowed_flags(rktio_t *rktio);
#/* Reports the flags that are accepted by `rktio_process` on the
#   current OS. */

#RKTIO_EXTERN_NOERR int rktio_process_pid(rktio_t *rktio, rktio_process_t *sp);
#/* Always succeeds, whether or not the process is still running, so
#   the result is generally not meaningful if the process is not
#   running. */

#RKTIO_EXTERN rktio_ok_t rktio_process_kill(rktio_t *rktio, rktio_process_t *sp);
#RKTIO_EXTERN rktio_ok_t rktio_process_interrupt(rktio_t *rktio, rktio_process_t *sp);
#/* Interrupts or kills a process; does not deallocate the process record. */

#RKTIO_EXTERN void rktio_process_forget(rktio_t *rktio, rktio_process_t *sp);
#/* Deallocates a process record, whether or not the process has
#   stopped. */

#RKTIO_EXTERN_ERR(RKTIO_PROCESS_ERROR)
#rktio_tri_t rktio_poll_process_done(rktio_t *rktio, rktio_process_t *sp);
#/* Check whether a process has completed: */
##define RKTIO_PROCESS_ERROR    (-2)
##define RKTIO_PROCESS_DONE     1
##define RKTIO_PROCESS_RUNNING  0

#typedef struct rktio_status_t {
#  rktio_bool_t running;
#  int result;
#} rktio_status_t;

#RKTIO_EXTERN rktio_status_t *rktio_process_status(rktio_t *rktio, rktio_process_t *sp);
#/* The `result` value is only value if `running` is 0. */

#RKTIO_EXTERN void rktio_reap_processes(rktio_t *rktio);
#/* If you start processes, calling this periodically may ensure that
#   resources are released sooner rather than later. */

#/*************************************************/
#/* Filesystem-change events                      */

#RKTIO_EXTERN_NOERR int rktio_fs_change_properties(rktio_t *rktio);
#/* Reports properties of the filesystem-change event implementation: */
##define RKTIO_FS_CHANGE_SUPPORTED   (1 << 0)
##define RKTIO_FS_CHANGE_SCALABLE    (1 << 1)
##define RKTIO_FS_CHANGE_LOW_LATENCY (1 << 2)
##define RKTIO_FS_CHANGE_FILE_LEVEL  (1 << 3)
##define RKTIO_FS_CHANGE_NEED_LTPS   (1 << 4)
class RKTIO_FS_CHANGE(_enum.IntFlag):
  RKTIO_FS_CHANGE_SUPPORTED   = _enum.auto()
  RKTIO_FS_CHANGE_SCALABLE    = _enum.auto()
  RKTIO_FS_CHANGE_LOW_LATENCY = _enum.auto()
  RKTIO_FS_CHANGE_FILE_LEVEL  = _enum.auto()
  RKTIO_FS_CHANGE_NEED_LTPS   = _enum.auto()
RKTIO_FS_CHANGE_SUPPORTED   = RKTIO_FS_CHANGE.RKTIO_FS_CHANGE_SUPPORTED  
RKTIO_FS_CHANGE_SCALABLE    = RKTIO_FS_CHANGE.RKTIO_FS_CHANGE_SCALABLE   
RKTIO_FS_CHANGE_LOW_LATENCY = RKTIO_FS_CHANGE.RKTIO_FS_CHANGE_LOW_LATENCY
RKTIO_FS_CHANGE_FILE_LEVEL  = RKTIO_FS_CHANGE.RKTIO_FS_CHANGE_FILE_LEVEL 
RKTIO_FS_CHANGE_NEED_LTPS   = RKTIO_FS_CHANGE.RKTIO_FS_CHANGE_NEED_LTPS  

#RKTIO_EXTERN_NOERR int rktio_fs_change_properties(rktio_t *rktio);
capi_rktio_fs_change_properties = librktio.rktio_fs_change_properties
capi_rktio_fs_change_properties.argtypes = [rktio_p]
capi_rktio_fs_change_properties.restype = int_t
def rktio_fs_change_properties(rktio):
  out = capi_call("rktio_fs_change_properties", check_rktio_p(rktio))
  return RKTIO_FS_CHANGE(out)

#typedef struct rktio_fs_change_t rktio_fs_change_t;
#struct rktio_ltps_t; /* forward reference */

# forward reference
class rktio_ltps_t(_c.Structure):
  pass
rktio_ltps_p = _c.POINTER(rktio_ltps_t)

class rktio_fs_change_t(_c.Structure):
  pass

rktio_fs_change_p = _c.POINTER(rktio_fs_change_t)

def check_rktio_fs_change_p(p, *args):
  return check_type(p, rktio_fs_change_p, "rktio_fs_change_p")

def check_rktio_fs_change_p_or_null(p, *args):
  return check_type_or_null(p, rktio_fs_change_p, "rktio_fs_change_p")

class RktioFsChange(CParameter):
  def __init__(self, rktio, path, p):
    typecheck_or_null(p, rktio_fs_change_p, "rktio_fs_change_p")
    super().__init__(p)
    self._rktio = check_rktio_p(rktio)
    self.path = path

  def unset(self):
    super().unset()
    self._rktio = None

  def __bool__(self):
    if not self._rktio:
      return False
    return super().__bool__()

  def dispose(self):
    if self:
      rktio_fs_change_forget(self._rktio, self)
    super().dispose()

  def __repr__(self):
    return f"RktioFsChange(path={self.path}, unwrap={unwrap(self)!r})"


#RKTIO_EXTERN rktio_fs_change_t *rktio_fs_change(rktio_t *rktio, rktio_const_string_t path,
#                                                struct rktio_ltps_t *ltps);
#/* Creates a filesystem-change tracker that reports changes in `path`
#   after creation of the tracker. The properties repotred by
#   `rktio_fs_change_properties` report various aspects of how the
#   tracker behaves. In particular, the `ltps` argument can be NULL
#   unless the `RKTIO_FS_CHANGE_NEED_LTPS` property is reported; if
#   `lt` is provided, then the tracker must be canceled or discovered
#   ready before `ltps` is closed. */
capi_rktio_fs_change = librktio.rktio_fs_change
capi_rktio_fs_change.argtypes = [rktio_p, rktio_const_string_t, rktio_ltps_p]
capi_rktio_fs_change.restype = rktio_fs_change_p
capi_rktio_fs_change.errcheck = check_rktio_ok_t
def rktio_fs_change(rktio, path, ltps=None):
  """Creates a filesystem-change tracker that reports changes in `path`
  after creation of the tracker. The properties repotred by
  `rktio_fs_change_properties` report various aspects of how the
  tracker behaves. In particular, the `ltps` argument can be NULL
  unless the `RKTIO_FS_CHANGE_NEED_LTPS` property is reported; if
  `lt` is provided, then the tracker must be canceled or discovered
  ready before `ltps` is closed."""
  need_ltps = bool(rktio_fs_change_properties(rktio) & RKTIO_FS_CHANGE_NEED_LTPS)
  if (ltps is None) != need_ltps:
    if not need_ltps:
      raise ValueError("RKTIO_FS_CHANGE doesn't need LTPS, but ltps wasn't None")
    else:
      raise ValueError("RKTIO_FS_CHANGE needs LTPS, but ltps was None")

  out = capi_call("rktio_fs_change", check_rktio_p(rktio), check_path(path), check_rktio_ltps_p_or_null(ltps))
  return RktioFsChange(rktio, path, out)

#RKTIO_EXTERN void rktio_fs_change_forget(rktio_t *rktio, rktio_fs_change_t *fc);
capi_rktio_fs_change_forget = librktio.rktio_fs_change_forget
capi_rktio_fs_change_forget.argtypes = [rktio_p, rktio_fs_change_p]
capi_rktio_fs_change_forget.restype = None
def rktio_fs_change_forget(rktio, fc):
  if ok(self := detach(fc, RktioFsChange)):
    fc = self
  out = capi_call("rktio_fs_change_forget", check_rktio_p(rktio), check_rktio_fs_change_p(fc))
  return out

#RKTIO_EXTERN_ERR(RKTIO_POLL_ERROR)
#rktio_tri_t rktio_poll_fs_change_ready(rktio_t *rktio, rktio_fs_change_t *fc);
#/* Returns one of `RKTIO_POLL_READY`, etc. */
capi_rktio_poll_fs_change_ready = librktio.rktio_poll_fs_change_ready
capi_rktio_poll_fs_change_ready.argtypes = [rktio_p, rktio_fs_change_p]
capi_rktio_poll_fs_change_ready.restype = rktio_ok_t
capi_rktio_poll_fs_change_ready.errcheck = check_rktio_poll_result
def rktio_poll_fs_change_ready(rktio, fc):
  out = capi_call("rktio_poll_fs_change_ready", check_rktio_p(rktio), check_rktio_fs_change_p(fc))
  return out

#/*************************************************/
#/* File-descriptor sets for polling              */

#/* A poll set works for a single use via `rktio_sleep`, as opposed to
#   "long-term" poll sets that can be used multiple times. The
#   `rktio_sleep` function accepts one of each and combines them. */

#typedef struct rktio_poll_set_t rktio_poll_set_t;
class rktio_poll_set_t(_c.Structure):
  """A poll set works for a single use via `rktio_sleep`, as opposed to
  "long-term" poll sets that can be used multiple times. The
  `rktio_sleep` function accepts one of each and combines them."""

rktio_poll_set_p = _c.POINTER(rktio_poll_set_t)

def check_rktio_poll_set_p(p, *args):
  return check_type(p, rktio_poll_set_p, "rktio_poll_set_p")

def check_rktio_poll_set_p_or_null(p, *args):
  return check_type_or_null(p, rktio_poll_set_p, "rktio_poll_set_p")

class RktioPollSet(CParameter):
  def __init__(self, rktio, p):
    typecheck_or_null(p, rktio_poll_set_p, "rktio_poll_set_p")
    super().__init__(p)
    self._rktio = check_rktio_p(rktio)

  def unset(self):
    super().unset()
    self._rktio = None

  def __bool__(self):
    if not self._rktio:
      return False
    return super().__bool__()

  def dispose(self):
    if self:
      rktio_poll_set_forget(self._rktio, self)
    super().dispose()


#RKTIO_EXTERN rktio_poll_set_t *rktio_make_poll_set(rktio_t *rktio);
capi_rktio_make_poll_set = librktio.rktio_make_poll_set
capi_rktio_make_poll_set.argtypes = [rktio_p]
capi_rktio_make_poll_set.restype = rktio_poll_set_p
capi_rktio_make_poll_set.errcheck = check_rktio_poll_set_p
def rktio_make_poll_set(rktio):
  out = capi_call("rktio_make_poll_set", check_rktio_p(rktio))
  return RktioPollSet(rktio, out)

#RKTIO_EXTERN void rktio_poll_set_forget(rktio_t *rktio, rktio_poll_set_t *fds);
#/* Don't reuse a poll set after calling `rktio_sleep`, but do
#   explicitly forget it afterward. */
capi_rktio_poll_set_forget = librktio.rktio_poll_set_forget
capi_rktio_poll_set_forget.argtypes = [rktio_p, rktio_poll_set_p]
capi_rktio_poll_set_forget.restype = None
def rktio_poll_set_forget(rktio, fds):
  """Don't reuse a poll set after calling `rktio_sleep`, but do
  explicitly forget it afterward."""
  if ok(self := detach(fds, RktioPollSet)):
    fds = self
  if fds:
    return capi_call("rktio_poll_set_forget", check_rktio_p(rktio), check_rktio_poll_set_p(fds))

#RKTIO_EXTERN void rktio_poll_add(rktio_t *rktio, rktio_fd_t *rfd, rktio_poll_set_t *fds, int modes);
#/* Registers a wait on a file descriptor in read and/or write mode or
#   flush mode. The flush mode corresponds to
#   `rktio_poll_write_flushed`.
#   `modes` values: */
##define RKTIO_POLL_READ   RKTIO_OPEN_READ
##define RKTIO_POLL_WRITE  RKTIO_OPEN_WRITE
##define RKTIO_POLL_FLUSH  (RKTIO_OPEN_WRITE << 2)
class RKTIO_POLL(_enum.IntEnum):
  RKTIO_POLL_READ = (1<<0) # RKTIO_OPEN_READ
  RKTIO_POLL_WRITE = (1<<1) # RKTIO_OPEN_WRITE
  RKTIO_POLL_FLUSH = ((1<<1) << 2) # (RKTIO_OPEN_WRITE << 2)
RKTIO_POLL_READ = RKTIO_POLL.RKTIO_POLL_READ
RKTIO_POLL_WRITE = RKTIO_POLL.RKTIO_POLL_WRITE
RKTIO_POLL_FLUSH = RKTIO_POLL.RKTIO_POLL_FLUSH
capi_rktio_poll_add = librktio.rktio_poll_add
capi_rktio_poll_add.argtypes = [rktio_p, rktio_fd_p, rktio_poll_set_p, int_t]
capi_rktio_poll_add.restype = None
def rktio_poll_add(rktio, rfd, fds, modes: RKTIO_POLL):
  """Registers a wait on a file descriptor in read and/or write mode or
  flush mode. The flush mode corresponds to
  `rktio_poll_write_flushed`."""
  return capi_call("rktio_poll_add", check_rktio_p(rktio), check_rktio_fd_p(rfd), check_rktio_poll_set_p(fds), int_t(RKTIO_POLL(modes)))

#RKTIO_EXTERN void rktio_poll_add_accept(rktio_t *rktio, rktio_listener_t *listener, rktio_poll_set_t *fds);
#RKTIO_EXTERN void rktio_poll_add_connect(rktio_t *rktio, rktio_connect_t *conn, rktio_poll_set_t *fds);
#RKTIO_EXTERN void rktio_poll_add_addrinfo_lookup(rktio_t *rktio, rktio_addrinfo_lookup_t *lookup, rktio_poll_set_t *fds);
capi_rktio_poll_add_addrinfo_lookup = librktio.rktio_poll_add_addrinfo_lookup
capi_rktio_poll_add_addrinfo_lookup.argtypes = [rktio_p, rktio_addrinfo_lookup_p, rktio_poll_set_p]
capi_rktio_poll_add_addrinfo_lookup.restype = None
def rktio_poll_add_addrinfo_lookup(rktio, lookup, fds):
  out = capi_call("rktio_poll_add_addrinfo_lookup", check_rktio_p(rktio), check_rktio_addrinfo_lookup_p(lookup), check_rktio_poll_set_p(fds))
  return out
#RKTIO_EXTERN void rktio_poll_add_process(rktio_t *rktio, rktio_process_t *sp, rktio_poll_set_t *fds);
#RKTIO_EXTERN void rktio_poll_add_fs_change(rktio_t *rktio, rktio_fs_change_t *fc, rktio_poll_set_t *fds);
capi_rktio_poll_add_fs_change = librktio.rktio_poll_add_fs_change
capi_rktio_poll_add_fs_change.argtypes = [rktio_p, rktio_fs_change_p, rktio_poll_set_p]
capi_rktio_poll_add_fs_change.restype = None
def rktio_poll_add_fs_change(rktio, fc, fds):
  out = capi_call("rktio_poll_add_fs_change", check_rktio_p(rktio), check_rktio_fs_change_p(fc), check_rktio_poll_set_p(fds))
  return out
#/* Registers various other waits. */

#RKTIO_EXTERN void rktio_poll_set_add_nosleep(rktio_t *rktio, rktio_poll_set_t *fds);
#/* Causes a sleep given `fds` to return immediately. */
capi_rktio_poll_set_add_nosleep = librktio.rktio_poll_set_add_nosleep
capi_rktio_poll_set_add_nosleep.argtypes = [rktio_p, rktio_poll_set_p]
capi_rktio_poll_set_add_nosleep.restype = None
def rktio_poll_set_add_nosleep(rktio, fds):
  """Causes a sleep given `fds` to return immediately."""
  return capi_call("rktio_poll_set_add_nosleep", check_rktio_p(rktio), check_rktio_poll_set_p(fds))

#RKTIO_EXTERN void rktio_poll_set_add_handle(rktio_t *rktio, intptr_t h, rktio_poll_set_t *fds, int repost);
#RKTIO_EXTERN void rktio_poll_set_add_eventmask(rktio_t *rktio, rktio_poll_set_t *fds, int mask);
#/* When sleeping on Windows, extra handles or eventmasks can be added
#   to trigger a wake up. The functions do nothing  on other platforms. */

#RKTIO_EXTERN void rkio_reset_sleep_backoff(rktio_t *rktio);
#/* Call this function when using `rktio_poll_set_add_eventmask` and
#   when matching events are not always consumed from the queue between
#   sleeps. To accommodate messages that are not consumed, the poll set
#   will actually only sleep a short while at first, and then back off
#   exponentially. Call this function when your program does useful
#   work (instead of spinning on sleep) to reset the backoff
#   counter. */

# capi_rkio_reset_sleep_backoff = librktio.rkio_reset_sleep_backoff
# capi_rkio_reset_sleep_backoff.argtypes = [rktio_p]
# capi_rkio_reset_sleep_backoff.restype = rktio_ok_t
# capi_rkio_reset_sleep_backoff.errcheck = check_rktio_ok_t
# def rkio_reset_sleep_backoff(rktio):
#   """Call this function when using `rktio_poll_set_add_eventmask` and
#   when matching events are not always consumed from the queue between
#   sleeps. To accommodate messages that are not consumed, the poll set
#   will actually only sleep a short while at first, and then back off
#   exponentially. Call this function when your program does useful
#   work (instead of spinning on sleep) to reset the backoff
#   counter."""
#   out = capi_call("rkio_reset_sleep_backoff", check_rktio_p(rktio))
#   return out

#/*************************************************/
#/* Long-term poll sets                           */

#/* "Long-term" means that the poll set will be used frequently with
#   incremental updates, which means that it's worthwhile to use an OS
#   facililty (epoll, kqueue, etc.) to speed up polling. */

#typedef struct rktio_ltps_t rktio_ltps_t;
#typedef struct rktio_ltps_handle_t rktio_ltps_handle_t;

# forward referenced above
# class rktio_ltps_t(_c.Structure):
#   pass
# rktio_ltps_p = _c.POINTER(rktio_ltps_t)

class rktio_ltps_handle_t(_c.Structure):
  pass
rktio_ltps_handle_p = _c.POINTER(rktio_ltps_handle_t)

def check_rktio_ltps_p(p, *args):
  return check_type(p, rktio_ltps_p, "rktio_ltps_p")

def check_rktio_ltps_p_or_null(p, *args):
  return check_type_or_null(p, rktio_ltps_p, "rktio_ltps_p")

def check_rktio_ltps_handle_p(p, *args):
  return check_type(p, rktio_ltps_handle_p, "rktio_ltps_handle_p")

def check_rktio_ltps_handle_p_or_null(p, *args):
  return check_type_or_null(p, rktio_ltps_handle_p, "rktio_ltps_handle_p")

class RktioLtps(CParameter):
  def __init__(self, rktio, p):
    typecheck_or_null(p, rktio_ltps_p, "rktio_ltps_p")
    super().__init__(p)
    self._rktio = check_rktio_p(rktio)

  def unset(self):
    super().unset()
    self._rktio = None

  def __bool__(self):
    if not self._rktio:
      return False
    return super().__bool__()

  def dispose(self):
    if self:
      rktio_ltps_close(self._rktio, self)
    super().dispose()

class RktioLtpsHandle(CParameter):
  def __init__(self, rktio, p):
    typecheck_or_null(p, rktio_ltps_handle_p, "rktio_ltps_handle_p")
    super().__init__(p)
    self._rktio = check_rktio_p(rktio)

  def unset(self):
    super().unset()
    self._rktio = None

  def __bool__(self):
    if not self._rktio:
      return False
    return super().__bool__()

  def dispose(self):
    # TODO: refcount?
    # if self:
    #   rktio_ltps_close(self._rktio, self)
    super().dispose()


#RKTIO_EXTERN rktio_ltps_t *rktio_ltps_open(rktio_t *rktio);
capi_rktio_ltps_open = librktio.rktio_ltps_open
capi_rktio_ltps_open.argtypes = [rktio_p]
capi_rktio_ltps_open.restype = rktio_ltps_p
capi_rktio_ltps_open.errcheck = check_rktio_ok_t
def rktio_ltps_open(rktio):
  out = capi_call("rktio_ltps_open", check_rktio_p(rktio))
  return RktioLtps(rktio, out)

#RKTIO_EXTERN void rktio_ltps_close(rktio_t *rktio, rktio_ltps_t *lt);
#/* Closing will signal all remianing handles and free all signaled
#   handles, but use `rktio_ltps_remove_all` and
#   `rktio_ltps_get_signaled_handle` is you need to clean up any
#   per-handle data: */
capi_rktio_ltps_close = librktio.rktio_ltps_close
capi_rktio_ltps_close.argtypes = [rktio_p, rktio_ltps_p]
capi_rktio_ltps_close.restype = None
capi_rktio_ltps_close.errcheck = check_rktio_ok_t
def rktio_ltps_close(rktio, ltps):
  if ok(self := detach(ltps, RktioLtps)):
    ltps = self
  if ltps:
    return capi_call("rktio_ltps_close", check_rktio_p(rktio), check_rktio_ltps_p(ltps))

#RKTIO_EXTERN rktio_ltps_handle_t *rktio_ltps_add(rktio_t *rktio, rktio_ltps_t *lt, rktio_fd_t *rfd, int mode);
#/* Don't free the returned handle; use it with `rktio_ltps_handle_set_data`
#   and `rktio_ltps_handle_get_data`, and free it only when the same handle
#   is returned by `rktio_ltps_get_signaled_handle`. Using the `RKTIO_LTPS_REMOVE`
#   mode causes a previous created handle to be signaled. A successful remove
#   reports `RKTIO_ERROR_LTPS_REMOVED` while returning NULL. A `...CHECK...`
#   or `...REMOVE...` mode that doesn't find the handle reports
#   `RKTIO_ERROR_LTPS_NOT_FOUND`.
#   `mode` values: */
#enum {
#  RKTIO_LTPS_CREATE_READ = 1,
#  RKTIO_LTPS_CREATE_WRITE,
#  RKTIO_LTPS_CHECK_READ,
#  RKTIO_LTPS_CHECK_WRITE,
#  RKTIO_LTPS_REMOVE,
#  /* Internal, for filesystem-change events with kqueue: */
#  RKTIO_LTPS_CREATE_VNODE,
#  RKTIO_LTPS_CHECK_VNODE,
#  RKTIO_LTPS_REMOVE_VNODE
#};
class RKTIO_LTPS(_enum.IntEnum):
  RKTIO_LTPS_CREATE_READ = 1
  RKTIO_LTPS_CREATE_WRITE = _enum.auto()
  RKTIO_LTPS_CHECK_READ = _enum.auto()
  RKTIO_LTPS_CHECK_WRITE = _enum.auto()
  RKTIO_LTPS_REMOVE = _enum.auto()
  # Internal, for filesystem-change events with kqueue:
  RKTIO_LTPS_CREATE_VNODE = _enum.auto()
  RKTIO_LTPS_CHECK_VNODE = _enum.auto()
  RKTIO_LTPS_REMOVE_VNODE = _enum.auto()
RKTIO_LTPS_CREATE_READ = RKTIO_LTPS.RKTIO_LTPS_CREATE_READ
RKTIO_LTPS_CREATE_WRITE = RKTIO_LTPS.RKTIO_LTPS_CREATE_WRITE
RKTIO_LTPS_CHECK_READ = RKTIO_LTPS.RKTIO_LTPS_CHECK_READ
RKTIO_LTPS_CHECK_WRITE = RKTIO_LTPS.RKTIO_LTPS_CHECK_WRITE
RKTIO_LTPS_REMOVE = RKTIO_LTPS.RKTIO_LTPS_REMOVE
RKTIO_LTPS_CREATE_VNODE = RKTIO_LTPS.RKTIO_LTPS_CREATE_VNODE
RKTIO_LTPS_CHECK_VNODE = RKTIO_LTPS.RKTIO_LTPS_CHECK_VNODE
RKTIO_LTPS_REMOVE_VNODE = RKTIO_LTPS.RKTIO_LTPS_REMOVE_VNODE

#RKTIO_EXTERN rktio_ltps_handle_t *rktio_ltps_add(rktio_t *rktio, rktio_ltps_t *lt, rktio_fd_t *rfd, int mode);
capi_rktio_ltps_add = librktio.rktio_ltps_add
capi_rktio_ltps_add.argtypes = [rktio_p, rktio_ltps_p, rktio_fd_p, int_t]
capi_rktio_ltps_add.restype = rktio_ltps_handle_p
capi_rktio_ltps_add.errcheck = check_rktio_ok_t
def rktio_ltps_add(rktio, lt, rfd, mode: RKTIO_LTPS):
  """Don't free the returned handle; use it with `rktio_ltps_handle_set_data`
  and `rktio_ltps_handle_get_data`, and free it only when the same handle
  is returned by `rktio_ltps_get_signaled_handle`. Using the `RKTIO_LTPS_REMOVE`
  mode causes a previous created handle to be signaled. A successful remove
  reports `RKTIO_ERROR_LTPS_REMOVED` while returning NULL. A `...CHECK...`
  or `...REMOVE...` mode that doesn't find the handle reports
  `RKTIO_ERROR_LTPS_NOT_FOUND`."""
  out = capi_call("rktio_ltps_add", check_rktio_p(rktio), check_rktio_ltps_p(lt), check_rktio_fd_p(rfd), int_t(RKTIO_LTPS(mode)))
  return RktioLtpsHandle(rktio, out)

#RKTIO_EXTERN void rktio_ltps_handle_set_data(rktio_t *rktio, rktio_ltps_handle_t *h, void *data);
capi_rktio_ltps_handle_set_data = librktio.rktio_ltps_handle_set_data
capi_rktio_ltps_handle_set_data.argtypes = [rktio_p, rktio_ltps_handle_p, void_p]
capi_rktio_ltps_handle_set_data.restype = None
def rktio_ltps_handle_set_data(rktio, h, data):
  out = capi_call("rktio_ltps_handle_set_data", check_rktio_p(rktio), check_rktio_ltps_handle_p(h), asvoidp(data))
  return out
#RKTIO_EXTERN_NOERR void *rktio_ltps_handle_get_data(rktio_t *rktio, rktio_ltps_handle_t *h);
capi_rktio_ltps_handle_get_data = librktio.rktio_ltps_handle_get_data
capi_rktio_ltps_handle_get_data.argtypes = [rktio_p, rktio_ltps_handle_p]
capi_rktio_ltps_handle_get_data.restype = void_p
def rktio_ltps_handle_get_data(rktio, h):
  out = capi_call("rktio_ltps_handle_get_data", check_rktio_p(rktio), check_rktio_ltps_handle_p(h))
  return out

#RKTIO_EXTERN void rktio_ltps_remove_all(rktio_t *rktio, rktio_ltps_t *lt);
#/* Removes all additions, signaling all handles. */
capi_rktio_ltps_remove_all = librktio.rktio_ltps_remove_all
capi_rktio_ltps_remove_all.argtypes = [rktio_p, rktio_ltps_p]
capi_rktio_ltps_remove_all.restype = None
def rktio_ltps_remove_all(rktio, lt):
  """Removes all additions, signaling all handles."""
  out = capi_call("rktio_ltps_remove_all", check_rktio_p(rktio), check_rktio_ltps_p(lt))
  return out

#RKTIO_EXTERN rktio_ok_t rktio_ltps_poll(rktio_t *rktio, rktio_ltps_t *lt);
#/* Enqueues signaled handles for retreival via `rktio_ltps_get_signaled_handle`.  */
capi_rktio_ltps_poll = librktio.rktio_ltps_poll
capi_rktio_ltps_poll.argtypes = [rktio_p, rktio_ltps_p]
capi_rktio_ltps_poll.restype = rktio_ok_t
capi_rktio_ltps_poll.errcheck = check_rktio_ok_t
def rktio_ltps_poll(rktio, lt):
  """Enqueues signaled handles for retreival via `rktio_ltps_get_signaled_handle`."""
  out = capi_call("rktio_ltps_poll", check_rktio_p(rktio), check_rktio_ltps_p(lt))
  return out

#RKTIO_EXTERN rktio_ltps_handle_t *rktio_ltps_get_signaled_handle(rktio_t *rktio, rktio_ltps_t *lt);
#/* Free the returned handle when you're done with it. */
capi_rktio_ltps_get_signaled_handle = librktio.rktio_ltps_get_signaled_handle
capi_rktio_ltps_get_signaled_handle.argtypes = [rktio_p, rktio_ltps_p]
capi_rktio_ltps_get_signaled_handle.restype = rktio_ltps_handle_p
capi_rktio_ltps_get_signaled_handle.errcheck = check_rktio_ok_t
def rktio_ltps_get_signaled_handle(rktio, lt):
  """Free the returned handle when you're done with it."""
  out = capi_call("rktio_ltps_get_signaled_handle", check_rktio_p(rktio), check_rktio_ltps_p(lt))
  return RktioLtpsHandle(rktio, out)

#RKTIO_EXTERN void rktio_ltps_handle_set_auto(rktio_t *rktio, rktio_ltps_handle_t *lth, int auto_mode);
#/* An alternative to receiving the handle via `rktio_ltps_get_signaled_handle`;
#   have signaling automatically either zero the handle content (so the
#   client can detect signaling) or free the handle (bcause the client
#   is no longer watching it). If `auto_mode` is `RKTIO_LTPS_HANDLE_NONE`,
#   automatic handling is disabled for the handle. */
#/* `auto_mode` values: */
#enum {
#  RKTIO_LTPS_HANDLE_NONE,
#  RKTIO_LTPS_HANDLE_ZERO,
#  RKTIO_LTPS_HANDLE_FREE
#};
class RKTIO_LTPS_HANDLE_AUTO(_enum.IntEnum):
  RKTIO_LTPS_HANDLE_NONE = 0
  RKTIO_LTPS_HANDLE_ZERO = _enum.auto()
  RKTIO_LTPS_HANDLE_FREE = _enum.auto()
RKTIO_LTPS_HANDLE_NONE = RKTIO_LTPS_HANDLE_AUTO.RKTIO_LTPS_HANDLE_NONE
RKTIO_LTPS_HANDLE_ZERO = RKTIO_LTPS_HANDLE_AUTO.RKTIO_LTPS_HANDLE_ZERO
RKTIO_LTPS_HANDLE_FREE = RKTIO_LTPS_HANDLE_AUTO.RKTIO_LTPS_HANDLE_FREE
#RKTIO_EXTERN void rktio_ltps_handle_set_auto(rktio_t *rktio, rktio_ltps_handle_t *lth, int auto_mode);
capi_rktio_ltps_handle_set_auto = librktio.rktio_ltps_handle_set_auto
capi_rktio_ltps_handle_set_auto.argtypes = [rktio_p, rktio_ltps_handle_p, int_t]
capi_rktio_ltps_handle_set_auto.restype = None
def rktio_ltps_handle_set_auto(rktio, lth, auto_mode=RKTIO_LTPS_HANDLE_NONE):
  """An alternative to receiving the handle via `rktio_ltps_get_signaled_handle`;
  have signaling automatically either zero the handle content (so the
  client can detect signaling) or free the handle (bcause the client
  is no longer watching it). If `auto_mode` is `RKTIO_LTPS_HANDLE_NONE`,
  automatic handling is disabled for the handle."""
  out = capi_call("rktio_ltps_handle_set_auto", check_rktio_p(rktio), check_rktio_ltps_handle_p(lth), RKTIO_LTPS_HANDLE_AUTO(mode))
  return out

brief = 1e-45
forever = float('inf')

#RKTIO_EXTERN RKTIO_BLOCKING void rktio_sleep(rktio_t *rktio, float nsecs, rktio_poll_set_t *fds, rktio_ltps_t *lt);
#/* Waits up to `nsecs` seconds (or forever if `nsecs` is 0), until
#   something registered with `fds` or `lt` is ready, or until there's
#   some other activity that sometimes causes an early wakeup. */
capi_rktio_sleep = librktio.rktio_sleep
capi_rktio_sleep.argtypes = [rktio_p, float_t, rktio_poll_set_p, rktio_ltps_p]
capi_rktio_sleep.restype = None
def rktio_sleep(rktio, nsecs: float = brief, fds: rktio_poll_set_p = None, lt: rktio_ltps_p = None):
  """Waits up to `nsecs` seconds (or forever if `nsecs` is infinity), until
  something registered with `fds` or `lt` is ready, or until there's
  some other activity that sometimes causes an early wakeup."""
  return capi_call("rktio_sleep", check_rktio_p(rktio), float_t(nsecs), check_rktio_poll_set_p_or_null(fds), check_rktio_ltps_p_or_null(lt))

#/*************************************************/
#/* Sleeping in a background thread               */

#RKTIO_EXTERN rktio_ok_t rktio_start_sleep(rktio_t *rktio, float nsecs, rktio_poll_set_t *fds, rktio_ltps_t *lt,
#                                          int woke_fd);
#/* Like `rktio_sleep`, but starts a sleep in a background thread. When the
#   background thread is done sleeping, it writes a byte to `woke_fd`, but the
#   background thread can be woken up with `rktio_end_sleep`. */

#RKTIO_EXTERN rktio_ok_t rktio_start_sleep(rktio_t *rktio, float nsecs, rktio_poll_set_t *fds, rktio_ltps_t *lt, int woke_fd);
capi_rktio_start_sleep = librktio.rktio_start_sleep
capi_rktio_start_sleep.argtypes = [rktio_p, float_t, rktio_poll_set_p, rktio_ltps_p, int_t]
capi_rktio_start_sleep.restype = rktio_ok_t
capi_rktio_start_sleep.errcheck = check_rktio_ok_t
def rktio_start_sleep(rktio, nsecs: float = brief, fds = None, lt = None, woke_fd: int = None):
  """Like `rktio_sleep`, but starts a sleep in a background thread. When the
  background thread is done sleeping, it writes a byte to `woke_fd`, but the
  background thread can be woken up with `rktio_end_sleep`."""
  fd = check_int(woke_fd, "woke_fd")
  out = capi_call("rktio_start_sleep", check_rktio_p(rktio), float_t(nsecs), check_rktio_poll_set_p_or_null(fds), check_rktio_ltps_p_or_null(lt), fd)
  return out

#RKTIO_EXTERN void rktio_end_sleep(rktio_t *rktio);
#/* Ends a background sleep started with `rktio_sleep`. Call this
#   function exactly once for each successful `rktio_start_sleep`,
#   whether or not the background thread write to `woke_fd` already. */
capi_rktio_end_sleep = librktio.rktio_end_sleep
capi_rktio_end_sleep.argtypes = [rktio_p]
capi_rktio_end_sleep.restype = None
def rktio_end_sleep(rktio):
  """Ends a background sleep started with `rktio_sleep`. Call this
  function exactly once for each successful `rktio_start_sleep`,
  whether or not the background thread write to `woke_fd` already."""
  out = capi_call("rktio_end_sleep", check_rktio_p(rktio))
  return out

#/*************************************************/
#/* Files, directories, and links                 */

#RKTIO_EXTERN rktio_bool_t rktio_file_exists(rktio_t *rktio, rktio_const_string_t filename);
capi_rktio_file_exists = librktio.rktio_file_exists
capi_rktio_file_exists.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_file_exists.restype = bool_t
def rktio_file_exists(rktio, filename):
  return capi_call("rktio_file_exists", check_rktio_p(rktio), _os.fsencode(filename))
#RKTIO_EXTERN rktio_bool_t rktio_directory_exists(rktio_t *rktio, rktio_const_string_t dirname);
capi_rktio_directory_exists = librktio.rktio_directory_exists
capi_rktio_directory_exists.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_directory_exists.restype = bool_t
def rktio_directory_exists(rktio, dirname):
  return capi_call("rktio_directory_exists", check_rktio_p(rktio), _os.fsencode(dirname))
#RKTIO_EXTERN rktio_bool_t rktio_link_exists(rktio_t *rktio, rktio_const_string_t filename);
capi_rktio_link_exists = librktio.rktio_link_exists
capi_rktio_link_exists.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_link_exists.restype = bool_t
def rktio_link_exists(rktio, filename):
  return capi_call("rktio_link_exists", check_rktio_p(rktio), _os.fsencode(filename))
#RKTIO_EXTERN rktio_bool_t rktio_is_regular_file(rktio_t *rktio, rktio_const_string_t filename);
#/* On Windows, check for special filenames (like "aux") before calling
#   the `rktio_file_exists` or `rktio_is_regular_file`. */
capi_rktio_is_regular_file = librktio.rktio_is_regular_file
capi_rktio_is_regular_file.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_is_regular_file.restype = bool_t
def rktio_is_regular_file(rktio, filename):
  """On Windows, check for special filenames (like "aux") before calling
  the `rktio_file_exists` or `rktio_is_regular_file`."""
  return capi_call("rktio_is_regular_file", check_rktio_p(rktio), _os.fsencode(filename))

##define RKTIO_FILE_TYPE_FILE           1
##define RKTIO_FILE_TYPE_DIRECTORY      2
##define RKTIO_FILE_TYPE_LINK           3
##define RKTIO_FILE_TYPE_DIRECTORY_LINK 4

##define RKTIO_FILE_TYPE_ERROR  (-1)

class RKTIO_FILE_TYPE(_enum.IntEnum):
  FILE           = 1
  DIRECTORY      = 2
  LINK           = 3
  DIRECTORY_LINK = 4
  ERROR          = -1

RKTIO_FILE_TYPE_FILE           = RKTIO_FILE_TYPE.FILE          
RKTIO_FILE_TYPE_DIRECTORY      = RKTIO_FILE_TYPE.DIRECTORY     
RKTIO_FILE_TYPE_LINK           = RKTIO_FILE_TYPE.LINK          
RKTIO_FILE_TYPE_DIRECTORY_LINK = RKTIO_FILE_TYPE.DIRECTORY_LINK
RKTIO_FILE_TYPE_ERROR          = RKTIO_FILE_TYPE.ERROR         

def check_rktio_file_type_result(result, *rest):
  #check_valid(None, result != RKTIO_FILE_TYPE_ERROR, *rest)
  check_valid(None, ok(result), *rest)
  if result == RKTIO_FILE_TYPE_ERROR:
    raise ValueError(RKTIO_FILE_TYPE_ERROR, *rest)
  return RKTIO_FILE_TYPE(result)

#RKTIO_EXTERN_ERR(RKTIO_FILE_TYPE_ERROR)
#int rktio_file_type(rktio_t *rktio, rktio_const_string_t filename);
#/* Result is `RKTIO_FILE_TYPE_ERROR` for error, otherwise one of
#   the `RKTIO_FILE_TYPE_...` values. On Windows, check for special
#   filenames (like "aux") before calling this function. */
capi_rktio_file_type = librktio.rktio_file_type
capi_rktio_file_type.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_file_type.restype = int_t
capi_rktio_file_type.errcheck = check_rktio_file_type_result
def rktio_file_type(rktio, filename):
  """Result is `RKTIO_FILE_TYPE_ERROR` for error, otherwise one of
  the `RKTIO_FILE_TYPE_...` values. On Windows, check for special
  filenames (like "aux") before calling this function."""
  out = capi_call("rktio_file_type", check_rktio_p(rktio), _os.fsencode(filename))
  return out

#RKTIO_EXTERN rktio_ok_t rktio_delete_file(rktio_t *rktio, rktio_const_string_t fn, rktio_bool_t enable_write_on_fail);
capi_rktio_delete_file = librktio.rktio_delete_file
capi_rktio_delete_file.argtypes = [rktio_p, rktio_const_string_t, rktio_bool_t]
capi_rktio_delete_file.restype = rktio_ok_t
capi_rktio_delete_file.errcheck = check_rktio_ok_t
def rktio_delete_file(rktio, filename, enable_write_on_fail: bool = True):
  out = capi_call("rktio_delete_file", check_rktio_p(rktio), _os.fsencode(filename), enable_write_on_fail)
  return out

#RKTIO_EXTERN rktio_ok_t rktio_rename_file(rktio_t *rktio, rktio_const_string_t dest, rktio_const_string_t src, rktio_bool_t exists_ok);
#/* Can report `RKTIO_ERROR_EXISTS`. */
capi_rktio_rename_file = librktio.rktio_rename_file
capi_rktio_rename_file.argtypes = [rktio_p, rktio_const_string_t, rktio_const_string_t, rktio_bool_t]
capi_rktio_rename_file.restype = rktio_ok_t
capi_rktio_rename_file.errcheck = check_rktio_ok_t
def rktio_rename_file(rktio, dest, src, exists_ok: bool):
  """Can report `RKTIO_ERROR_EXISTS`."""
  out = capi_call("rktio_rename_file", check_rktio_p(rktio), _os.fsencode(dest), _os.fsencode(src), exists_ok)
  return out

#RKTIO_EXTERN char *rktio_get_current_directory(rktio_t *rktio);
capi_rktio_get_current_directory = librktio.rktio_get_current_directory
capi_rktio_get_current_directory.argtypes = [rktio_p]
capi_rktio_get_current_directory.restype = void_p
capi_rktio_get_current_directory.errcheck = check_directory_path
def rktio_get_current_directory(r: rktio_p):
  return capi_call("capi_rktio_get_current_directory", check_rktio_p(r))

#RKTIO_EXTERN rktio_ok_t rktio_set_current_directory(rktio_t *rktio, rktio_const_string_t path);
capi_rktio_set_current_directory = librktio.rktio_set_current_directory
capi_rktio_set_current_directory.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_set_current_directory.restype = rktio_ok_t
capi_rktio_set_current_directory.errcheck = check_rktio_ok_t
def rktio_set_current_directory(r: rktio_p, path):
  return capi_call("capi_rktio_set_current_directory", check_rktio_p(r), os.fsencode(path))

#RKTIO_EXTERN rktio_ok_t rktio_make_directory(rktio_t *rktio, rktio_const_string_t filename);
#/* Can report `RKTIO_ERROR_EXISTS`. */
capi_rktio_make_directory = librktio.rktio_make_directory
capi_rktio_make_directory.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_make_directory.restype = rktio_ok_t
capi_rktio_make_directory.errcheck = check_rktio_ok_t
def rktio_make_directory(rktio, filename):
  """Can report `RKTIO_ERROR_EXISTS`."""
  out = capi_call("rktio_make_directory", check_rktio_p(rktio), _os.fsencode(filename))
  return out

#RKTIO_EXTERN rktio_ok_t rktio_make_directory_with_permissions(rktio_t *rktio, rktio_const_string_t filename, int perm_bits);
#/* Can report `RKTIO_ERROR_EXISTS`. */
##define RKTIO_DEFAULT_DIRECTORY_PERM_BITS 0777
RKTIO_DEFAULT_DIRECTORY_PERM_BITS = 0o777

capi_rktio_make_directory_with_permissions = librktio.rktio_make_directory_with_permissions
capi_rktio_make_directory_with_permissions.argtypes = [rktio_p, rktio_const_string_t, int_t]
capi_rktio_make_directory_with_permissions.restype = rktio_ok_t
capi_rktio_make_directory_with_permissions.errcheck = check_rktio_ok_t
def rktio_make_directory_with_permissions(rktio, filename, perm_bits: int = RKTIO_DEFAULT_DIRECTORY_PERM_BITS):
  out = capi_call("rktio_make_directory_with_permissions", check_rktio_p(rktio), _os.fsencode(filename), perm_bits)
  return out

#RKTIO_EXTERN rktio_ok_t rktio_delete_directory(rktio_t *rktio, rktio_const_string_t filename, rktio_const_string_t current_directory,
#                                               rktio_bool_t enable_write_on_fail);
#/* The `current_directory` argument is used on Windows to avoid being
#   in `filename` (instead) as a directory while trying to delete it.
#   The `enable_write_on_fail` argument also applied to Windows. */

#RKTIO_EXTERN char *rktio_readlink(rktio_t *rktio, rktio_const_string_t fullfilename);
#/* Argument should not have a trailing separator. Can report
#   `RKTIO_ERROR_NOT_A_LINK`. */
capi_rktio_readlink = librktio.rktio_readlink
capi_rktio_readlink.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_readlink.restype = char_p
capi_rktio_readlink.errcheck = check_rktio_ok_t
def rktio_readlink(rktio, fullfilename):
  """Argument should not have a trailing separator. Can report
  `RKTIO_ERROR_NOT_A_LINK`."""
  out = capi_call("rktio_readlink", check_rktio_p(rktio), _os.fsencode(fullfilename))
  return _os.fsdecode(out)

#RKTIO_EXTERN rktio_ok_t rktio_make_link(rktio_t *rktio, rktio_const_string_t src, rktio_const_string_t dest,
#                                        rktio_bool_t dest_is_directory);
#/* The `dest_is_directory` argument is used only
#   on Windows. Can report `RKTIO_ERROR_EXISTS`. */
capi_rktio_make_link = librktio.rktio_make_link
capi_rktio_make_link.argtypes = [rktio_p, rktio_const_string_t, rktio_const_string_t, rktio_bool_t]
capi_rktio_make_link.restype = rktio_ok_t
capi_rktio_make_link.errcheck = check_rktio_ok_t
def rktio_make_link(rktio, src, dest, dest_is_directory: bool):
  out = capi_call("rktio_make_link", check_rktio_p(rktio), _os.fsencode(src), _os.fsencode(dest), dest_is_directory)
  return out

#/*************************************************/
#/* File attributes                               */

#typedef intptr_t rktio_timestamp_t;
rktio_timestamp_t = intptr_t
rktio_timestamp_p = _c.POINTER(rktio_timestamp_t)

def out_rktio_timestamp(ptr, *rest):
  return out_rktio_value(ptr, rktio_timestamp_p, *rest)

#RKTIO_EXTERN rktio_filesize_t *rktio_file_size(rktio_t *rktio, rktio_const_string_t filename);
capi_rktio_file_size = librktio.rktio_file_size
capi_rktio_file_size.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_file_size.restype = rktio_filesize_p
capi_rktio_file_size.errcheck = out_rktio_filesize
def rktio_file_size(rktio, filepath: _os.PathLike):
  return capi_call("capi_rktio_file_size", check_rktio_p(rktio), in_path(filepath))

#RKTIO_EXTERN rktio_timestamp_t *rktio_get_file_modify_seconds(rktio_t *rktio, rktio_const_string_t file);
capi_rktio_get_file_modify_seconds = librktio.rktio_get_file_modify_seconds
capi_rktio_get_file_modify_seconds.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_get_file_modify_seconds.restype = rktio_timestamp_p
capi_rktio_get_file_modify_seconds.errcheck = out_rktio_timestamp
def rktio_get_file_modify_seconds(rktio, filepath: _os.PathLike):
  return capi_call("capi_rktio_get_file_modify_seconds", check_rktio_p(rktio), in_path(filepath))
#RKTIO_EXTERN rktio_ok_t rktio_set_file_modify_seconds(rktio_t *rktio, rktio_const_string_t file, rktio_timestamp_t secs);
capi_rktio_set_file_modify_seconds = librktio.rktio_set_file_modify_seconds
capi_rktio_set_file_modify_seconds.argtypes = [rktio_p, char_p, rktio_timestamp_t]
capi_rktio_set_file_modify_seconds.restype = rktio_ok_t
capi_rktio_set_file_modify_seconds.errcheck = check_rktio_ok_t
def rktio_set_file_modify_seconds(rktio, filepath: _os.PathLike, secs: int):
  return capi_call("rktio_set_file_modify_seconds", check_rktio_p(rktio), in_path(filepath), rktio_timestamp_t(secs))

#typedef struct rktio_stat_t {
#  /* Eventually, this should use `int64_t`, available in C99 and up */
#  uintptr_t device_id, inode, mode, hardlink_count, user_id, group_id,
#            device_id_for_special_file, size, block_size, block_count,
#            access_time_seconds, access_time_nanoseconds,
#            modify_time_seconds, modify_time_nanoseconds,
#            ctime_seconds, ctime_nanoseconds;
#  /* The `st_ctime` field is status change time for Posix and creation time
#     for Windows. */
#  rktio_bool_t ctime_is_change_time;
#} rktio_stat_t;
@dataclasses.dataclass(frozen=True)
class rktio_stat_t(_c.Structure):
  device_id: int
  inode: int
  mode: int
  hardlink_count: int
  user_id: int
  group_id: int

  device_id_for_special_file: int
  size: int
  block_size: int
  block_count: int

  access_time_seconds: int
  access_time_nanoseconds: int

  modify_time_seconds: int
  modify_time_nanoseconds: int

  # The `st_ctime` field is status change time for Posix and creation time
  # for Windows.
  ctime_seconds: int
  ctime_nanoseconds: int
  ctime_is_change_time: bool

  #  /* Eventually, this should use `int64_t`, available in C99 and up */
  #  uintptr_t device_id, inode, mode, hardlink_count, user_id, group_id,
  #            device_id_for_special_file, size, block_size, block_count,
  #            access_time_seconds, access_time_nanoseconds,
  #            modify_time_seconds, modify_time_nanoseconds,
  #            ctime_seconds, ctime_nanoseconds;
  _fields_ = [(name, uintptr_t) for name in """
               device_id inode mode hardlink_count user_id group_id
               device_id_for_special_file size block_size block_count
               access_time_seconds access_time_nanoseconds
               modify_time_seconds modify_time_nanoseconds
               ctime_seconds ctime_nanoseconds""".split()
               ] + [
                   ("ctime_is_change_time", rktio_bool_t),
                   ]

rktio_stat_p = _c.POINTER(rktio_stat_t)

#RKTIO_EXTERN rktio_stat_t *rktio_file_or_directory_stat(rktio_t *rktio, rktio_const_string_t path, rktio_bool_t follow_links);
capi_rktio_file_or_directory_stat = librktio.rktio_file_or_directory_stat
capi_rktio_file_or_directory_stat.argtypes = [rktio_p, rktio_const_string_t, rktio_bool_t]
capi_rktio_file_or_directory_stat.restype = rktio_stat_p
capi_rktio_file_or_directory_stat.errcheck = check_rktio_ok_t
def rktio_file_or_directory_stat(rktio, path, follow_links: bool = True):
  out = capi_call("rktio_file_or_directory_stat", check_rktio_p(rktio), _os.fsencode(path), follow_links)
  return out.contents

#typedef struct rktio_identity_t {
#  uintptr_t a, b, c;
#  int a_bits, b_bits, c_bits; /* size of each in bits */
#} rktio_identity_t;

@dataclasses.dataclass(frozen=True)
class rktio_identity_t(_c.Structure):
  a: int
  b: int
  c: int

  # size of each in bits
  a_bits: int
  b_bits: int
  c_bits: int

  def __hash__(self):
    return hash((self.a, self.b, self.c, self.a_bits, self.b_bits, self.c_bits))

  _fields_ = [
      ("a", uintptr_t),
      ("b", uintptr_t),
      ("c", uintptr_t),
      ("a_bits", int_t),
      ("b_bits", int_t),
      ("c_bits", int_t),
      ]

rktio_identity_p = _c.POINTER(rktio_identity_t)

#RKTIO_EXTERN rktio_identity_t *rktio_fd_identity(rktio_t *rktio, rktio_fd_t *fd);
capi_rktio_fd_identity = librktio.rktio_fd_identity
capi_rktio_fd_identity.argtypes = [rktio_p, rktio_fd_p]
capi_rktio_fd_identity.restype = rktio_identity_p
capi_rktio_fd_identity.errcheck = check_rktio_ok_t
def rktio_fd_identity(rktio, fd):
  out = capi_call("rktio_fd_identity", check_rktio_p(rktio), check_rktio_fd_p(fd))
  return out.contents
#RKTIO_EXTERN rktio_identity_t *rktio_path_identity(rktio_t *rktio, rktio_const_string_t path, rktio_bool_t follow_links);
capi_rktio_path_identity = librktio.rktio_path_identity
capi_rktio_path_identity.argtypes = [rktio_p, rktio_const_string_t, rktio_bool_t]
capi_rktio_path_identity.restype = rktio_identity_p
capi_rktio_path_identity.errcheck = check_rktio_ok_t
def rktio_path_identity(rktio, path, follow_links: bool = True):
  out = capi_call("rktio_path_identity", check_rktio_p(rktio), _os.fsencode(path), follow_links)
  return out.contents

#/*************************************************/
#/* Permissions                                   */

#/* Should match OS bits: */
##define RKTIO_PERMISSION_READ  0x4
##define RKTIO_PERMISSION_WRITE 0x2
##define RKTIO_PERMISSION_EXEC  0x1
class RKTIO_PERMISSION(_enum.IntFlag):
  READ  = 0x4
  WRITE = 0x2
  EXEC  = 0x1
RKTIO_PERMISSION_READ  = RKTIO_PERMISSION.READ
RKTIO_PERMISSION_WRITE = RKTIO_PERMISSION.WRITE
RKTIO_PERMISSION_EXEC  = RKTIO_PERMISSION.EXEC

##define RKTIO_PERMISSION_ERROR (-1)
RKTIO_PERMISSION_ERROR = -1

def check_rktio_permission_result(result, *rest):
  # check_valid(None, result != RKTIO_PERMISSION_ERROR, *rest)
  check_valid(None, ok(result), *rest)
  if result == RKTIO_PERMISSION_ERROR:
    raise ValueError(result)
  return result

#RKTIO_EXTERN_ERR(RKTIO_PERMISSION_ERROR)
#int rktio_get_file_or_directory_permissions(rktio_t *rktio, rktio_const_string_t filename, rktio_bool_t all_bits);
#/* Result is `RKTIO_PERMISSION_ERROR` for error, otherwise a combination of
#   bits. If not `all_bits`, then use constants above. */
capi_rktio_get_file_or_directory_permissions = librktio.rktio_get_file_or_directory_permissions
capi_rktio_get_file_or_directory_permissions.argtypes = [rktio_p, rktio_const_string_t, rktio_bool_t]
capi_rktio_get_file_or_directory_permissions.restype = rktio_ok_t
capi_rktio_get_file_or_directory_permissions.errcheck = check_rktio_permission_result
def rktio_get_file_or_directory_permissions(rktio, filename, all_bits: bool = True):
  """Result is `RKTIO_PERMISSION_ERROR` for error, otherwise a combination of
  bits. If not `all_bits`, then use constants above."""
  out = capi_call("rktio_get_file_or_directory_permissions", check_rktio_p(rktio), _os.fsencode(filename), all_bits)
  return out

#RKTIO_EXTERN rktio_ok_t rktio_set_file_or_directory_permissions(rktio_t *rktio, rktio_const_string_t filename, int new_bits);
#/* The `new_bits` format corresponds to `all_bits` for getting permissions.
#   Can report `RKTIO_ERROR_BAD_PERMISSION` for bits that make no sense. */
capi_rktio_set_file_or_directory_permissions = librktio.rktio_set_file_or_directory_permissions
capi_rktio_set_file_or_directory_permissions.argtypes = [rktio_p, rktio_const_string_t, int_t]
capi_rktio_set_file_or_directory_permissions.restype = rktio_ok_t
capi_rktio_set_file_or_directory_permissions.errcheck = check_rktio_ok_t
def rktio_set_file_or_directory_permissions(rktio, filename, new_bits):
  """The `new_bits` format corresponds to `all_bits` for getting permissions.
  Can report `RKTIO_ERROR_BAD_PERMISSION` for bits that make no sense."""
  out = capi_call("rktio_set_file_or_directory_permissions", check_rktio_p(rktio), _os.fsencode(filename), new_bits)
  return out

#/*************************************************/
#/* Directory listing                             */

#typedef struct rktio_directory_list_t rktio_directory_list_t;
class rktio_directory_list_t(_c.Structure):
  pass

rktio_directory_list_p = _c.POINTER(rktio_directory_list_t)

def check_rktio_directory_list_p(p, *args):
  return check_type(p, rktio_directory_list_p, "rktio_directory_list_p")

def check_rktio_directory_list_p_or_null(p, *args):
  return check_type_or_null(p, rktio_directory_list_p, "rktio_directory_list_p")

class RktioDirectoryList(CParameter):
  def __init__(self, rktio, p):
    typecheck_or_null(p, rktio_directory_list_p, "rktio_directory_list_p")
    super().__init__(p)
    self._rktio = check_rktio_p(rktio)

  def unset(self):
    super().unset()
    self._rktio = None

  def __bool__(self):
    if not self._rktio:
      return False
    return super().__bool__()

  def dispose(self):
    # this was crashing on process exit; skip for now.
    # if self:
    #   rktio_directory_list_stop(self._rktio, self)
    super().dispose()

#RKTIO_EXTERN rktio_directory_list_t *rktio_directory_list_start(rktio_t *rktio, rktio_const_string_t dirname);
#/* On Windows, the given `dirname` must be normalized and not have
#   `.` or `..`: */
capi_rktio_directory_list_start = librktio.rktio_directory_list_start
capi_rktio_directory_list_start.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_directory_list_start.restype = rktio_directory_list_p
capi_rktio_directory_list_start.errcheck = check_rktio_ok_t
def rktio_directory_list_start(rktio, dirname):
  """On Windows, the given `dirname` must be normalized and not have
  `.` or `..`:"""
  out = capi_call("rktio_directory_list_start", check_rktio_p(rktio), _os.fsencode(dirname))
  return RktioDirectoryList(rktio, out)

#RKTIO_EXTERN char *rktio_directory_list_step(rktio_t *rktio, rktio_directory_list_t *dl);
#/* Returns an unallocated "" and deallocates `dl` when the iteration
#   is complete. A NULL result would mean an error without deallocating
#   `dl`, but that doesn't currently happen. */
capi_rktio_directory_list_step = librktio.rktio_directory_list_step
capi_rktio_directory_list_step.argtypes = [rktio_p, rktio_directory_list_p]
capi_rktio_directory_list_step.restype = char_p
capi_rktio_directory_list_step.errcheck = check_rktio_ok_t
def rktio_directory_list_step(rktio, dl):
  """Returns an unallocated "" and deallocates `dl` when the iteration
  is complete. A NULL result would mean an error without deallocating
  `dl`, but that doesn't currently happen."""
  out = capi_call("rktio_directory_list_step", check_rktio_p(rktio), check_rktio_directory_list_p(dl))
  if not out:
    # dl is now deallocated; ensure its pointer is removed.
    detach(dl, RktioDirectoryList)
    if dl:
      # dl shouldn't be valid after detach
      breakpoint()
  else:
    return _os.fsdecode(out)

#RKTIO_EXTERN void rktio_directory_list_stop(rktio_t *rktio, rktio_directory_list_t *dl);
#/* Interrupt a directory list in progress, not needed after
#   `rktio_directory_list_step` returns "": */
capi_rktio_directory_list_stop = librktio.rktio_directory_list_stop
capi_rktio_directory_list_stop.argtypes = [rktio_p]
capi_rktio_directory_list_stop.restype = None
def rktio_directory_list_stop(rktio, dl):
  """Interrupt a directory list in progress, not needed after
  `rktio_directory_list_step` returns "":"""
  if ok(self := detach(dl, RktioDirectoryList)):
    dl = self
  if dl:
    out = capi_call("rktio_directory_list_stop", check_rktio_p(rktio), check_rktio_directory_list_p(dl))
    return out

def listdir(rktio, dirname):
  dl = rktio_directory_list_start(rktio, dirname)
  while ok(it := rktio_directory_list_step(rktio, dl)):
    yield it

def check_list_of_strings(out, *rest):
  if out:
    strings = []
    for n in itertools.count():
      it = dynamic_array(char_p, out, n + 1)
      if it[n] is None:
        strings = it[:n]
        break
    rktio_free(out)
    return tuple(strings)
  else:
    raise ValueError("expected pointer", out)

def check_list_of_paths(out, *rest):
  strings = check_list_of_strings(out, *rest)
  return tuple(_os.fsdecode(path) for path in strings)

#RKTIO_EXTERN char **rktio_filesystem_roots(rktio_t *rktio);
#/* Returns a NULL-terminated array. Free each string. Currently never
#   errors. */
capi_rktio_filesystem_roots = librktio.rktio_filesystem_roots
capi_rktio_filesystem_roots.argtypes = [rktio_p]
capi_rktio_filesystem_roots.restype = void_p
capi_rktio_filesystem_roots.errcheck = check_list_of_paths
def rktio_filesystem_roots(rktio):
  """Returns a NULL-terminated array. Free each string. Currently never
  errors."""
  out = capi_call("rktio_filesystem_roots", check_rktio_p(rktio))
  return out

#/*************************************************/
#/* File copying                                  */

#typedef struct rktio_file_copy_t rktio_file_copy_t;

#RKTIO_EXTERN_STEP rktio_file_copy_t *rktio_copy_file_start(rktio_t *rktio, rktio_const_string_t dest, rktio_const_string_t src,
#                                                           rktio_bool_t exists_ok);
#/* Starts a file copy. Depending on the OS, this step may perform the
#   whole copy, or it may just get started. Can report
#   `RKTIO_ERROR_EXISTS`, and sets an error step as listed further below. */

#RKTIO_EXTERN rktio_bool_t rktio_copy_file_is_done(rktio_t *rktio, rktio_file_copy_t *fc);
#RKTIO_EXTERN_STEP rktio_ok_t rktio_copy_file_step(rktio_t *rktio, rktio_file_copy_t *fc);
#/* As long as the copy isn't done, call `rktio_copy_file_step` to make
#   a little progress. Use `rktio_copy_file_finish_permissions`
#   (optionally) and then `rktio_copy_file_stop` when done. An error
#   sets an error step as listed further below. */

#RKTIO_EXTERN_STEP rktio_ok_t rktio_copy_file_finish_permissions(rktio_t *rktio, rktio_file_copy_t *fc);
#/* Depending on the OS, copies permissions from the source to the
#   destination. This step can be performed at any time between the
#   start and stop. Reports success if this step isn't needed (e.g.,
#   where a copy fully completes when it is started). On error, the
#   step is set to `RKTIO_COPY_STEP_WRITE_DEST_METADATA`. */

#RKTIO_EXTERN void rktio_copy_file_stop(rktio_t *rktio, rktio_file_copy_t *fc);
#/* Deallocates the copy process, interrupting it if the copy is not
#   complete. */

#/* Step values for errors from `rktio_copy_file_start` and
#   `rktio_copy_file_step`: */
#enum {
#  RKTIO_COPY_STEP_UNKNOWN,
#  RKTIO_COPY_STEP_OPEN_SRC,
#  RKTIO_COPY_STEP_OPEN_DEST,
#  RKTIO_COPY_STEP_READ_SRC_DATA,
#  RKTIO_COPY_STEP_WRITE_DEST_DATA,
#  RKTIO_COPY_STEP_READ_SRC_METADATA,
#  RKTIO_COPY_STEP_WRITE_DEST_METADATA
#};

#/*************************************************/
#/* System paths                                  */

#RKTIO_EXTERN char *rktio_system_path(rktio_t *rktio, int which);
#/* `which` values: */
#enum {
#  RKTIO_PATH_SYS_DIR,
#  RKTIO_PATH_TEMP_DIR,
#  RKTIO_PATH_PREF_DIR,
#  RKTIO_PATH_PREF_FILE,
#  RKTIO_PATH_ADDON_DIR,
#  RKTIO_PATH_HOME_DIR,
#  RKTIO_PATH_DESK_DIR,
#  RKTIO_PATH_DOC_DIR,
#  RKTIO_PATH_INIT_DIR,
#  RKTIO_PATH_INIT_FILE,
#  RKTIO_PATH_CACHE_DIR
#};

class RKTIO_PATH(_enum.IntEnum):
  RKTIO_PATH_SYS_DIR    = 0
  RKTIO_PATH_TEMP_DIR   = _enum.auto()
  RKTIO_PATH_PREF_DIR   = _enum.auto()
  RKTIO_PATH_PREF_FILE  = _enum.auto()
  RKTIO_PATH_ADDON_DIR  = _enum.auto()
  RKTIO_PATH_HOME_DIR   = _enum.auto()
  RKTIO_PATH_DESK_DIR   = _enum.auto()
  RKTIO_PATH_DOC_DIR    = _enum.auto()
  RKTIO_PATH_INIT_DIR   = _enum.auto()
  RKTIO_PATH_INIT_FILE  = _enum.auto()
  RKTIO_PATH_CACHE_DIR  = _enum.auto()

RKTIO_PATH_SYS_DIR    = RKTIO_PATH.RKTIO_PATH_SYS_DIR   
RKTIO_PATH_TEMP_DIR   = RKTIO_PATH.RKTIO_PATH_TEMP_DIR  
RKTIO_PATH_PREF_DIR   = RKTIO_PATH.RKTIO_PATH_PREF_DIR  
RKTIO_PATH_PREF_FILE  = RKTIO_PATH.RKTIO_PATH_PREF_FILE 
RKTIO_PATH_ADDON_DIR  = RKTIO_PATH.RKTIO_PATH_ADDON_DIR 
RKTIO_PATH_HOME_DIR   = RKTIO_PATH.RKTIO_PATH_HOME_DIR  
RKTIO_PATH_DESK_DIR   = RKTIO_PATH.RKTIO_PATH_DESK_DIR  
RKTIO_PATH_DOC_DIR    = RKTIO_PATH.RKTIO_PATH_DOC_DIR   
RKTIO_PATH_INIT_DIR   = RKTIO_PATH.RKTIO_PATH_INIT_DIR  
RKTIO_PATH_INIT_FILE  = RKTIO_PATH.RKTIO_PATH_INIT_FILE 
RKTIO_PATH_CACHE_DIR  = RKTIO_PATH.RKTIO_PATH_CACHE_DIR 

capi_rktio_system_path = librktio.rktio_system_path
capi_rktio_system_path.argtypes = [rktio_p, int_t]
capi_rktio_system_path.restype = char_p
capi_rktio_system_path.errcheck = check_rktio_ok_t
def rktio_system_path(rktio, which: RKTIO_PATH):
  out = capi_call("rktio_system_path", check_rktio_p(rktio), int(RKTIO_PATH(which)))
  return _os.fsdecode(out)

#RKTIO_EXTERN char *rktio_expand_user_tilde(rktio_t *rktio, rktio_const_string_t filename);
#/* Path must start with tilde, otherwise `RKTIO_ERROR_NO_TILDE`.
#   Other possible errors are `RKTIO_ERROR_ILL_FORMED_USER` and
#   `RKTIO_ERROR_UNKNOWN_USER`. */
capi_rktio_expand_user_tilde = librktio.rktio_expand_user_tilde
capi_rktio_expand_user_tilde.argtypes = [rktio_p, rktio_const_string_t]
capi_rktio_expand_user_tilde.restype = char_p
capi_rktio_expand_user_tilde.errcheck = check_rktio_ok_t
def rktio_expand_user_tilde(rktio, filename):
  """Path must start with tilde, otherwise `RKTIO_ERROR_NO_TILDE`.
  Other possible errors are `RKTIO_ERROR_ILL_FORMED_USER` and
  `RKTIO_ERROR_UNKNOWN_USER`."""
  out = capi_call("rktio_expand_user_tilde", check_rktio_p(rktio), _os.fsencode(filename))
  return _os.fsdecode(out)

#RKTIO_EXTERN_NOERR char *rktio_uname(rktio_t *rktio);
#/* Returns a string describing the current machine and installation,
#   similar to the return of `uname -a` on Unix. If machine information
#   cannot be obtained for some reason, the result is a copy of
#   "<unknown machine>". */
capi_rktio_uname = librktio.rktio_uname
capi_rktio_uname.argtypes = [rktio_p]
capi_rktio_uname.restype = char_p
capi_rktio_uname.errcheck = check_rktio_ok_t
def rktio_uname(rktio):
  """Returns a string describing the current machine and installation,
  similar to the return of `uname -a` on Unix. If machine information
  cannot be obtained for some reason, the result is a copy of
  "<unknown machine>"."""
  out = capi_call("rktio_uname", check_rktio_p(rktio))
  return _os.fsdecode(out)

#/*************************************************/
#/* Sleep and signals                             */

#typedef struct rktio_signal_handle_t rktio_signal_handle_t;
#/* A `rktio_signal_handle_t` is a value specific to a `rktio_t` that
#   causes any `rktio_sleep` for that `rktio_t` to return (or causes
#   the next `rktio_sleep` to return if one is not in progress. */

class rktio_signal_handle_t(_c.Structure):
  """A `rktio_signal_handle_t` is a value specific to a `rktio_t` that
  causes any `rktio_sleep` for that `rktio_t` to return (or causes
  the next `rktio_sleep` to return if one is not in progress."""

rktio_signal_handle_p = _c.POINTER(rktio_signal_handle_t)

def check_rktio_signal_handle_p(p, *args):
  return check_type(p, rktio_signal_handle_p, "rktio_signal_handle_p")

def check_rktio_signal_handle_p_or_null(p, *args):
  return check_type_or_null(p, rktio_signal_handle_p, "rktio_signal_handle_p")

class RktioSignalHandle(CParameter):
  def __init__(self, h):
    typecheck_or_null(h, rktio_signal_handle_p, "rktio_signal_handle_p")
    super().__init__(h)

  def dispose(self):
    if p := unwrap(self):
      rktio_free(self)
    super().dispose()


#RKTIO_EXTERN_NOERR rktio_signal_handle_t *rktio_get_signal_handle(rktio_t *rktio);
#/* Gets the handle for the given `rktio_t`. */
capi_rktio_get_signal_handle = librktio.rktio_get_signal_handle
capi_rktio_get_signal_handle.argtypes = [rktio_p]
capi_rktio_get_signal_handle.restype = rktio_signal_handle_p
def rktio_get_signal_handle(rktio):
  """Gets the handle for the given `rktio_t`."""
  out = capi_call("capi_rktio_get_signal_handle", check_rktio_p(rktio))
  return RktioSignalHandle(out)


#RKTIO_EXTERN void rktio_signal_received_at(rktio_signal_handle_t *h);
#/* Signals the given handle. This function can be called from any
#   thread or from signal handlers. */
capi_rktio_signal_received_at = librktio.rktio_signal_received_at
capi_rktio_signal_received_at.argtypes = [rktio_signal_handle_p]
capi_rktio_signal_received_at.restype = None
def rktio_signal_received_at(h):
  """Signals the given handle. This function can be called from any
  thread or from signal handlers."""
  return capi_call("rktio_signal_received_at", check_rktio_signal_handle_p(h))

#RKTIO_EXTERN void rktio_signal_received(rktio_t *rktio);
#/* A shorthand for `rktio_signal_received_at` composed with
#   `rktio_get_signal_handle`. */
capi_rktio_signal_received = librktio.rktio_signal_received
capi_rktio_signal_received.argtypes = [rktio_p]
capi_rktio_signal_received.restype = None
def rktio_signal_received(rktio):
  """A shorthand for `rktio_signal_received_at` composed with
  `rktio_get_signal_handle`."""
  return capi_call("capi_rktio_signal_received", check_rktio_p(rktio))

#RKTIO_EXTERN void rktio_wait_until_signal_received(rktio_t *rktio);
#/* The same as `rktio_sleep` with no timeout, no poll set, and no
#   long-term poll set. */
capi_rktio_wait_until_signal_received = librktio.rktio_wait_until_signal_received
capi_rktio_wait_until_signal_received.argtypes = [rktio_p]
capi_rktio_wait_until_signal_received.restype = None
def rktio_wait_until_signal_received(rktio):
  """The same as `rktio_sleep` with no timeout, no poll set, and no
  long-term poll set."""
  return capi_call("capi_rktio_wait_until_signal_received", check_rktio_p(rktio))

#RKTIO_EXTERN void rktio_flush_signals_received(rktio_t *rktio);
#/* Clears any pending signal so that it doesn't interrupt the next
#   `rktio_sleep`. */
capi_rktio_flush_signals_received = librktio.rktio_flush_signals_received
capi_rktio_flush_signals_received.argtypes = [rktio_p]
capi_rktio_flush_signals_received.restype = None
def rktio_flush_signals_received(rktio):
  """Clears any pending signal so that it doesn't interrupt the next
  `rktio_sleep`."""
  return capi_call("capi_rktio_flush_signals_received", check_rktio_p(rktio))

#RKTIO_EXTERN void rktio_install_os_signal_handler(rktio_t *rktio);
#/* Installs OS-level handlers for SIGINT, SIGTERM, and SIGHUP (or
#   Ctl-C on Windows) to signal the handle of `rktio` and also records
#   the signal for reporting via `rktio_poll_os_signal`. Only one
#   `rktio` can be registered this way at a time. This function must
#   not be called in two threads at the same time; more generally, it
#   can only be called when `rktio_will_modify_os_signal_handler`
#   can be called for SIGINT, etc. */
capi_rktio_install_os_signal_handler = librktio.rktio_install_os_signal_handler
capi_rktio_install_os_signal_handler.argtypes = [rktio_p]
capi_rktio_install_os_signal_handler.restype = None
def rktio_install_os_signal_handler(rktio):
  """Installs OS-level handlers for SIGINT, SIGTERM, and SIGHUP (or
  Ctl-C on Windows) to signal the handle of `rktio` and also records
  the signal for reporting via `rktio_poll_os_signal`. Only one
  `rktio` can be registered this way at a time. This function must
  not be called in two threads at the same time; more generally, it
  can only be called when `rktio_will_modify_os_signal_handler`
  can be called for SIGINT, etc."""
  return capi_call("capi_rktio_install_os_signal_handler", check_rktio_p(rktio))

#RKTIO_EXTERN_NOERR int rktio_poll_os_signal(rktio_t *rktio);
#/* Returns one of the following, not counting the last one: */
capi_rktio_poll_os_signal = librktio.rktio_poll_os_signal
capi_rktio_poll_os_signal.argtypes = [rktio_p]
capi_rktio_poll_os_signal.restype = int_t
def rktio_poll_os_signal(rktio):
  return RKTIO_OS_SIGNAL(capi_call("capi_rktio_poll_os_signal", check_rktio_p(rktio)))
##define RKTIO_OS_SIGNAL_NONE (-1)
#enum {
#  RKTIO_OS_SIGNAL_INT,
#  RKTIO_OS_SIGNAL_TERM,
#  RKTIO_OS_SIGNAL_HUP,
#  RKTIO_NUM_OS_SIGNALS
#};
class RKTIO_OS_SIGNAL(_enum.IntEnum):
  RKTIO_OS_SIGNAL_NONE = -1
  RKTIO_OS_SIGNAL_INT = 0
  RKTIO_OS_SIGNAL_TERM = 1
  RKTIO_OS_SIGNAL_HUP = 2
  RKTIO_NUM_OS_SIGNALS = 3

RKTIO_OS_SIGNAL_NONE = RKTIO_OS_SIGNAL.RKTIO_OS_SIGNAL_NONE
RKTIO_OS_SIGNAL_INT = RKTIO_OS_SIGNAL.RKTIO_OS_SIGNAL_INT
RKTIO_OS_SIGNAL_TERM = RKTIO_OS_SIGNAL.RKTIO_OS_SIGNAL_TERM
RKTIO_OS_SIGNAL_HUP = RKTIO_OS_SIGNAL.RKTIO_OS_SIGNAL_HUP
RKTIO_NUM_OS_SIGNALS = RKTIO_OS_SIGNAL.RKTIO_NUM_OS_SIGNALS


#RKTIO_EXTERN void rktio_will_modify_os_signal_handler(int sig_id);
#/* Registers with rktio that an operating-system signal handler is
#   about to be modified within the process but outside of rktio, where
#   `sig_id` is a signal identifier --- such as SIGINT or SIGTERM. This
#   notification allows rktio to record the current signal disposition
#   so that it can be restored after forking a new Unix process. Signal
#   registrations should happen only before multiple threads use rktio,
#   and registration of the signal can happen before any `rktio_init`
#   call. After a signal is registered, trying to re-register it after
#   threads start is harmless. */
capi_rktio_will_modify_os_signal_handler = librktio.rktio_will_modify_os_signal_handler
capi_rktio_will_modify_os_signal_handler.argtypes = [int_t]
capi_rktio_will_modify_os_signal_handler.restype = None
def rktio_will_modify_os_signal_handler(sig_id):
  """Registers with rktio that an operating-system signal handler is
  about to be modified within the process but outside of rktio, where
  `sig_id` is a signal identifier --- such as SIGINT or SIGTERM. This
  notification allows rktio to record the current signal disposition
  so that it can be restored after forking a new Unix process. Signal
  registrations should happen only before multiple threads use rktio,
  and registration of the signal can happen before any `rktio_init`
  call. After a signal is registered, trying to re-register it after
  threads start is harmless."""
  return capi_call("capi_rktio_will_modify_os_signal_handler", check_int(sig_id))


#/*************************************************/
#/* Time and date                                 */

#typedef struct rktio_date_t {
#  int nanosecond, second, minute, hour, day, month;
#  intptr_t year;
#  int day_of_week;
#  int day_of_year;
#  int is_dst;
#  int zone_offset;
#  char *zone_name; /* can be NULL; otherwise, free it */
#} rktio_date_t;

@dataclasses.dataclass
class rktio_date_t(_c.Structure):
  year: int
  month: int
  day: int
  hour: int
  minute: int
  second: int
  nanosecond: int
  zone_name: str
  zone_offset: int
  is_dst: int
  day_of_week: int
  day_of_year: int
  _fields_ = [
      ('nanosecond', int_t),
      ('second', int_t),
      ('minute', int_t),
      ('hour', int_t),
      ('day', int_t),
      ('month', int_t),
      ('year', intptr_t),
      ('day_of_week', int_t),
      ('day_of_year', int_t),
      ('is_dst', int_t),
      ('zone_offset', int_t),
      ('zone_name_', char_p),
      ]

  @property
  def zone_name(self) -> str:
    if ok(it := self.zone_name_):
      return asutf8(it)

rktio_date_p = _c.POINTER(rktio_date_t)

def check_rktio_date_p(p, *args):
  return check_type(p, rktio_date_p, "rktio_date_p")

def check_rktio_date_p_or_null(p, *args):
  return check_type_or_null(p, rktio_date_p, "rktio_date_p")

#RKTIO_EXTERN_NOERR uintptr_t rktio_get_milliseconds(void);
#/* Wll-clock time. Overflow may cause the result to wrap around to 0,
#   at least on a 32-bit platform. */
capi_rktio_get_milliseconds = librktio.rktio_get_milliseconds
capi_rktio_get_milliseconds.argtypes = []
capi_rktio_get_milliseconds.restype = uintptr_t
def rktio_get_milliseconds():
  """Wall-clock time. Overflow may cause the result to wrap around to 0,
  at least on a 32-bit platform."""
  out = capi_call("rktio_get_milliseconds")
  return out

#RKTIO_EXTERN_NOERR double rktio_get_inexact_milliseconds(void);
#/* Wall-clock time. No overflow, but won't strictly increase if the
#   system clock is reset. */
capi_rktio_get_inexact_milliseconds = librktio.rktio_get_inexact_milliseconds
capi_rktio_get_inexact_milliseconds.argtypes = []
capi_rktio_get_inexact_milliseconds.restype = double_t
def rktio_get_inexact_milliseconds():
  """Wall-clock time. No overflow, but won't strictly increase if the
  system clock is reset."""
  out = capi_call("rktio_get_inexact_milliseconds")
  return out

#RKTIO_EXTERN_NOERR double rktio_get_inexact_monotonic_milliseconds(rktio_t *rktio);
#/* Real time like wall-clock time, but will strictly increase,
#   assuming that the host system provides a monotonic clock. */
capi_rktio_get_inexact_monotonic_milliseconds = librktio.rktio_get_inexact_monotonic_milliseconds
capi_rktio_get_inexact_monotonic_milliseconds.argtypes = [rktio_p]
capi_rktio_get_inexact_monotonic_milliseconds.restype = double_t
def rktio_get_inexact_monotonic_milliseconds(rktio):
  """Real time like wall-clock time, but will strictly increase,
  assuming that the host system provides a monotonic clock."""
  out = capi_call("rktio_get_inexact_monotonic_milliseconds", check_rktio_p(rktio))
  return out

#RKTIO_EXTERN_NOERR uintptr_t rktio_get_process_milliseconds(rktio_t *rktio);
capi_rktio_get_process_milliseconds = librktio.rktio_get_process_milliseconds
capi_rktio_get_process_milliseconds.argtypes = [rktio_p]
capi_rktio_get_process_milliseconds.restype = uintptr_t
def rktio_get_process_milliseconds(rktio):
  """CPU time across all threads withing the process. Overflow may cause
  the result to wrap around to 0, at least on a 32-bit platform."""
  out = capi_call("rktio_get_process_milliseconds", check_rktio_p(rktio))
  return out
#RKTIO_EXTERN_NOERR uintptr_t rktio_get_process_children_milliseconds(rktio_t *rktio);
capi_rktio_get_process_children_milliseconds = librktio.rktio_get_process_children_milliseconds
capi_rktio_get_process_children_milliseconds.argtypes = [rktio_p]
capi_rktio_get_process_children_milliseconds.restype = uintptr_t
def rktio_get_process_children_milliseconds(rktio):
  """CPU time across all threads withing the process. Overflow may cause
  the result to wrap around to 0, at least on a 32-bit platform."""
  out = capi_call("rktio_get_process_children_milliseconds", check_rktio_p(rktio))
  return out
#/* CPU time across all threads withing the process. Overflow may cause
#   the result to wrap around to 0, at least on a 32-bit platform. */

#RKTIO_EXTERN_NOERR rktio_timestamp_t rktio_get_seconds(rktio_t *rktio);
capi_rktio_get_seconds = librktio.rktio_get_seconds
capi_rktio_get_seconds.argtypes = [rktio_p]
capi_rktio_get_seconds.restype = rktio_timestamp_t
def rktio_get_seconds(rktio):
  out = capi_call("rktio_get_seconds", check_rktio_p(rktio))
  return out

#RKTIO_EXTERN rktio_date_t *rktio_seconds_to_date(rktio_t *rktio, rktio_timestamp_t seconds, int nanoseconds, int get_gmt);
#/* A timestamp can be negative to represent a date before 1970. */
capi_rktio_seconds_to_date = librktio.rktio_seconds_to_date
capi_rktio_seconds_to_date.argtypes = [rktio_p, rktio_timestamp_t, int_t, int_t]
capi_rktio_seconds_to_date.restype = rktio_date_p
capi_rktio_seconds_to_date.errcheck = check_rktio_ok_t
def rktio_seconds_to_date(rktio, seconds: int, nanoseconds: int, get_gmt: bool = True):
  """A timestamp can be negative to represent a date before 1970."""
  out = capi_call("rktio_seconds_to_date", check_rktio_p(rktio), seconds, nanoseconds, get_gmt)
  return out.contents

def rktio_get_date(rktio, seconds: float = None, get_gmt: bool = True):
  if seconds is None:
    seconds = rktio_get_inexact_milliseconds() / 1000
  # sec = int(msec // 1000)
  # nsec = int((msec % 1000) * 1e6)
  sec = int(seconds)
  nsec = int(((seconds * 1000) % 1000) * 1e6)
  return rktio_seconds_to_date(rktio, sec, nsec, get_gmt)

#/*************************************************/
#/* Windows ShellExecute                          */

#enum {
#  RKTIO_SW_HIDE,
#  RKTIO_SW_MAXIMIZE,
#  RKTIO_SW_MINIMIZE,
#  RKTIO_SW_RESTORE,
#  RKTIO_SW_SHOW,
#  RKTIO_SW_SHOWDEFAULT,
#  RKTIO_SW_SHOWMAXIMIZED,
#  RKTIO_SW_SHOWMINIMIZED,
#  RKTIO_SW_SHOWMINNOACTIVE,
#  RKTIO_SW_SHOWNA,
#  RKTIO_SW_SHOWNOACTIVATE,
#  RKTIO_SW_SHOWNORMAL
#};

#RKTIO_EXTERN RKTIO_MSG_QUEUE rktio_ok_t rktio_shell_execute(rktio_t *rktio,
#                                                            rktio_const_string_t verb,
#                                                            rktio_const_string_t target,
#                                                            rktio_const_string_t arg,
#                                                            rktio_const_string_t dir,
#                                                            int show_mode);
#/* Supported only on Windows to run `ShellExecute`. The `dir` argument
#   needs to have normalized path separators. */

#/*************************************************/
#/* Path conversion                               */

#RKTIO_EXTERN rktio_char16_t *rktio_path_to_wide_path(rktio_t *rktio, rktio_const_string_t p);
#RKTIO_EXTERN_NOERR char *rktio_wide_path_to_path(rktio_t *rktio, const rktio_char16_t *wp);
#/* Convert to/from the OS's native path representation. These
#   functions are useful only on Windows. The `rktio_path_to_wide_path`
#   function can fail and report `RKTIO_ERROR_INVALID_PATH`. */

#/*************************************************/
#/* Processor count                               */

#RKTIO_EXTERN_NOERR int rktio_processor_count(rktio_t *rktio);
#/* Returns the number of processing units, either as CPUs, cores, or
#   hyoperthreads. */
capi_rktio_processor_count = librktio.rktio_processor_count
capi_rktio_processor_count.argtypes = [rktio_p]
capi_rktio_processor_count.restype = int_t
def rktio_processor_count(rktio: rktio_p):
  """Returns the number of processing units, either as CPUs, cores, or
  hyperthreads."""
  return capi_call("capi_rktio_processor_count", check_rktio_p(rktio))

#/*************************************************/
#/* Logging                                       */

#RKTIO_EXTERN rktio_ok_t rktio_syslog(rktio_t *rktio, int level, rktio_const_string_t name, rktio_const_string_t msg,
#                                     rktio_const_string_t exec_name);
#/* Adds a message to the system log. The `name` argument can be NULL,
#   and it is added to the front of the message with a separating ": "
#   if non_NULL. The `exec_name` is the current executable name; it's
#   currently, used only on Windows, and the value may matter only the
#   first time that `rktio_syslog` is called. */
#/* `level` values: */
#enum {
#  RKTIO_LOG_FATAL = 1,
#  RKTIO_LOG_ERROR,
#  RKTIO_LOG_WARNING,
#  RKTIO_LOG_INFO,
#  RKTIO_LOG_DEBUG
#};

#/*************************************************/
#/* Encoding conversion                           */

#RKTIO_EXTERN_NOERR int rktio_convert_properties(rktio_t *rktio);
#/* Returns a combination of the following flags. */

##define RKTIO_CONVERTER_SUPPORTED   (1 << 0)
##define RKTIO_CONVERT_STRCOLL_UTF16 (1 << 1)
##define RKTIO_CONVERT_RECASE_UTF16  (1 << 2)

#typedef struct rktio_converter_t rktio_converter_t;

#RKTIO_EXTERN rktio_converter_t *rktio_converter_open(rktio_t *rktio, rktio_const_string_t to_enc, rktio_const_string_t from_enc);
#/* Creates an encoding converter. */

#RKTIO_EXTERN void rktio_converter_close(rktio_t *rktio, rktio_converter_t *cvt);
#/* Destroys an encoding converter. */

#RKTIO_EXTERN_ERR(RKTIO_CONVERT_ERROR)
#intptr_t rktio_convert(rktio_t *rktio,
#                       rktio_converter_t *cvt,
#                       char **in, intptr_t *in_left,
#                       char **out, intptr_t *out_left);
#/* Converts some bytes, following the icon protocol: each consumed by
#   increments `*in` and decrements `*in_left`, and each produced by
#   increments `*out` and decrements `*out_left`. In case of an error,
#   the result is `RKTIO_CONVERT_ERROR` and the last error is set to
#   one of `RKTIO_ERROR_CONVERT_NOT_ENOUGH_SPACE`,
#   `RKTIO_ERROR_CONVERT_BAD_SEQUENCE`, or `RKTIO_ERROR_CONVERT_OTHER`
#   --- but an error indicates something within `in` or `out`,
#   and some bytes may have been successfully converted even if an
#   error is reported. */

##define RKTIO_CONVERT_ERROR (-1)

#typedef struct rktio_convert_result_t {
#  intptr_t in_consumed;  /* input bytes converted */
#  intptr_t out_produced; /* output bytes produced */
#  intptr_t converted;    /* characters converted, can be `RKTIO_CONVERT_ERROR` */
#} rktio_convert_result_t;

#RKTIO_EXTERN rktio_convert_result_t *rktio_convert_in(rktio_t *rktio,
#                                                      rktio_converter_t *cvt,
#                                                      char *in, intptr_t in_start, intptr_t in_end,
#                                                      char *out, intptr_t out_start, intptr_t out_end);
#/* The same as rktio_convert`, but accepting start and end positions
#   and returning results as an allocated struct. A conversion error
#   doesn't return a NULL result; instead, `converted` in the result
#   reports the error. */

#RKTIO_EXTERN void rktio_convert_reset(rktio_t *rktio, rktio_converter_t *cvt);
#/* Resets a converter to its initial state. */

#RKTIO_EXTERN_NOERR char *rktio_locale_recase(rktio_t *rktio,
#                                             rktio_bool_t to_up,
#                                             rktio_const_string_t in);
#/* Upcases (of `to_up`) or downcases (if `!to_up`) the content of `in`
#   using the current locale's encoding and case conversion. */

#RKTIO_EXTERN_NOERR rktio_char16_t *rktio_recase_utf16(rktio_t *rktio,
#                                                      rktio_bool_t to_up, rktio_char16_t *s1,
#                                                      intptr_t len, intptr_t *olen);
#/* Converts the case of a string encoded in UTF-16 for the system's
#   default locale if the OS provided direct support for it. The
#   `RKTIO_CONVERT_RECASE_UTF16 property from
#   `rktio_convert_properties` reports whether this functon will work.
#   Takes and optionally returns a length (`olen` can be NULL), but the
#   UTF-16 sequence is expected to have no nuls. */

#RKTIO_EXTERN_NOERR int rktio_locale_strcoll(rktio_t *rktio, rktio_const_string_t s1, rktio_const_string_t s2);
#/* Returns -1 if `s1` is less than `s2` by the current locale's
#   comparison, positive is `s1` is greater, and 0 if the strings
#   are equal. */

#RKTIO_EXTERN_NOERR int rktio_strcoll_utf16(rktio_t *rktio,
#                                           rktio_char16_t *s1, intptr_t l1,
#                                           rktio_char16_t *s2, intptr_t l2,
#                                           rktio_bool_t cvt_case);
#/* Compares two strings encoded in UTF-16 for the system's default
#   locale if the OS provided direct support for it. The
#   `RKTIO_CONVERT_STRCOLL_UTF16 property from
#   `rktio_convert_properties` reports whether this functon will work.
#   Takes lengths, but the UTF-16 sequences are expected to have
#   no include nuls. */

#RKTIO_EXTERN char *rktio_locale_encoding(rktio_t *rktio);
#/* Returns the name of the current locale's encoding. */

#RKTIO_EXTERN void rktio_set_locale(rktio_t *rktio, rktio_const_string_t name);
#/* Sets the current locale, which affects rktio string comparisons and
#   conversions. It can also affect the C library's character-property
#   predicates and number printing/parsing by setting a thread-local or
#   process-wide locale, but that effect is not guaranteed. The empty
#   string corresponds to the OS's native locale, and a NULL string
#   pointer corresponds to the C locale. */

#RKTIO_EXTERN void rktio_set_default_locale(rktio_const_string_t name);
#/* Similar to rktio_set_locale(), but sets the locale process-wide. */

#RKTIO_EXTERN_NOERR void *rktio_push_c_numeric_locale(rktio_t *rktio);
#RKTIO_EXTERN void rktio_pop_c_numeric_locale(rktio_t *rktio, void *prev);
#/* Use this pair of functions to temporarily switch the locale to the
#   C locale for number parsing and printing. Unlike
#   rktio_set_locale(), these functions set and restore the
#   thread-local or even process-wide locale. The result of the first
#   function is deallocated when passed to second function. */

#RKTIO_EXTERN char *rktio_system_language_country(rktio_t *rktio);
#/* Returns the current system's language in country in a 5-character
#   format such as "en_US". */
capi_rktio_system_language_country = librktio.rktio_system_language_country
capi_rktio_system_language_country.argtypes = [rktio_p]
capi_rktio_system_language_country.restype = char_p
capi_rktio_system_language_country.errcheck = check_rktio_ok_t
def rktio_system_language_country(rktio):
  """Returns the current system's language in country in a 5-character
  format such as "en_US"."""
  out = capi_call("rktio_system_language_country", check_rktio_p(rktio))
  return out


#/*************************************************/
#/* SHA-1, SHA-224, SHA-256                       */

#/* From Steve Reid's implementation at https://www.ghostscript.com/ */

#typedef struct rktio_sha1_ctx_t {
#  unsigned int state[5];
#  unsigned int count[2];
#  unsigned char buffer[64];
#} rktio_sha1_ctx_t;

##define RKTIO_SHA1_DIGEST_SIZE 20

#RKTIO_EXTERN void rktio_sha1_init(rktio_sha1_ctx_t *context);
#/* Initialize a context, which is memory of length `rktio_sha1_ctx_size()`
#   containing no pointers. */

#RKTIO_EXTERN void rktio_sha1_update(rktio_sha1_ctx_t *context,
#                                    const unsigned char *data, intptr_t start, intptr_t end);
#/* Add some bytes to the hash. */

#RKTIO_EXTERN void rktio_sha1_final(rktio_sha1_ctx_t *context, unsigned char *digest /* RKTIO_SHA1_DIGEST_SIZE */);
#/* Get the final hash value after all bytes have been added. */

#typedef struct rktio_sha2_ctx_t {
#    unsigned total[2];
#    unsigned state[8];
#    unsigned char buffer[64];
#    int is224;
#} rktio_sha2_ctx_t;

##define RKTIO_SHA224_DIGEST_SIZE 28
##define RKTIO_SHA256_DIGEST_SIZE 32

#RKTIO_EXTERN void rktio_sha2_init(rktio_sha2_ctx_t *ctx, rktio_bool_t is224);
#RKTIO_EXTERN void rktio_sha2_update(rktio_sha2_ctx_t *ctx,
#                                    const unsigned char *data, intptr_t start, intptr_t end);
#RKTIO_EXTERN void rktio_sha2_final(rktio_sha2_ctx_t *ctx, unsigned char *digest /* RKTIO_SHA2{24,56}_DIGEST_SIZE */);

#/*************************************************/
#/* Dynamically loaded libraries                  */

#typedef struct rktio_dll_t rktio_dll_t;

#RKTIO_EXTERN rktio_dll_t *rktio_dll_open(rktio_t *rktio, rktio_const_string_t name, rktio_bool_t as_global);
#/* Loads a DLL using system-provided functions and search rules, such
#   as dlopen() and its rules. If `as_global` is true, then the library
#   is loaded in "global" mode, which has implications for other
#   libraries trying to find bindings and for searching within the
#   specific library for a binding. The `name` argument can be NULL
#   to mean "the current executable".

#   Some system error-reporting protocols do not fit nicely into the
#   normal rktio error model. If the `RKTIO_ERROR_DLL` error is
#   reported, then rktio_dll_get_error() must be used before any other
#   `rktio_dll_...` call to get an error string.

#   If a DLL has been loaded with `name` already, the previous result
#   is returned again, but with an internal reference count returned.
#   The `as_global` argument matters only for the first load of a DLL
#   thrrough a given `name`.

#   Unless the DLL is explicitly unloaded with `rktio_dll_close`, even
#   when the given `rktio` is closed with `rktio_destroy`, loaded
#   libraries remain in the process. */

#RKTIO_EXTERN void *rktio_dll_find_object(rktio_t *rktio, rktio_dll_t *dll, rktio_const_string_t name);
#/* Find an address within `dll` for the `name` export.

#   An error result can be `RKTIO_ERROR_DLL` as for `rktio_dll_open`. */

#RKTIO_EXTERN rktio_ok_t rktio_dll_close(rktio_t *rktio, rktio_dll_t *dll);
#/* Decrements the reference count on `dll`, and if it goes to zero,
#   unloads the DLL using system-provided functions and destroys the
#   `dll` argument.

#   An error result can be `RKTIO_ERROR_DLL` as for `rktio_dll_open`. */

#RKTIO_EXTERN char *rktio_dll_get_error(rktio_t *rktio);
#/* Returns an error for a previous `rktio_dll_...` call, or NULL
#   if no error string is available or has already been returned.
#   See `rktio_dll_open` for more information. */

#typedef void *(*dll_open_proc)(rktio_const_string_t name, rktio_bool_t as_global);
#typedef void *(*dll_find_object_proc)(void *h, rktio_const_string_t name);
#typedef void (*dll_close_proc)(void *h);
#RKTIO_EXTERN void rktio_set_dll_procs(dll_open_proc dll_open,
#                                      dll_find_object_proc dll_find_object,
#                                      dll_close_proc dll_close);
#/* Installs procedures that are tried before native mechanisms,
#   currently only supported for Windows. */



# /*************************************************/
# /* Errors                                        */

# RKTIO_EXTERN_NOERR int rktio_get_last_error_kind(rktio_t *rktio);
capi_rktio_get_last_error_kind = librktio.rktio_get_last_error_kind
capi_rktio_get_last_error_kind.argtypes = [rktio_p]
capi_rktio_get_last_error_kind.restype = int_t
def rktio_get_last_error_kind(rktio):
  kind = capi_call("rktio_get_last_error_kind", check_rktio_p(rktio))
  return RKTIO_ERROR_KIND(kind)

# /* Kinds of error values: */
# enum {
#   RKTIO_ERROR_KIND_POSIX,
#   RKTIO_ERROR_KIND_WINDOWS,
#   RKTIO_ERROR_KIND_GAI,
#   RKTIO_ERROR_KIND_RACKET
# };
class RKTIO_ERROR_KIND(_enum.IntEnum):
  RKTIO_ERROR_KIND_POSIX = 0
  RKTIO_ERROR_KIND_WINDOWS = _enum.auto()
  RKTIO_ERROR_KIND_GAI = _enum.auto()
  RKTIO_ERROR_KIND_RACKET = _enum.auto()

RKTIO_ERROR_KIND_POSIX = RKTIO_ERROR_KIND.RKTIO_ERROR_KIND_POSIX
RKTIO_ERROR_KIND_WINDOWS = RKTIO_ERROR_KIND.RKTIO_ERROR_KIND_WINDOWS
RKTIO_ERROR_KIND_GAI = RKTIO_ERROR_KIND.RKTIO_ERROR_KIND_GAI
RKTIO_ERROR_KIND_RACKET = RKTIO_ERROR_KIND.RKTIO_ERROR_KIND_RACKET


# /* Error IDs of kind RKTIO_ERROR_KIND_RACKET */
# enum {
#   RKTIO_ERROR_UNSUPPORTED = 1,
#   RKTIO_ERROR_INVALID_PATH, /* Windows path-decoding failure */
#   RKTIO_ERROR_DOES_NOT_EXIST,
#   RKTIO_ERROR_EXISTS,
#   RKTIO_ERROR_ACCESS_DENIED,
#   RKTIO_ERROR_LINK_FAILED,
#   RKTIO_ERROR_NOT_A_LINK,
#   RKTIO_ERROR_BAD_PERMISSION,
#   RKTIO_ERROR_IS_A_DIRECTORY,
#   RKTIO_ERROR_NOT_A_DIRECTORY,
#   RKTIO_ERROR_UNSUPPORTED_TEXT_MODE,
#   RKTIO_ERROR_CANNOT_FILE_POSITION,
#   RKTIO_ERROR_NO_TILDE,
#   RKTIO_ERROR_ILL_FORMED_USER,
#   RKTIO_ERROR_UNKNOWN_USER,
#   RKTIO_ERROR_INIT_FAILED,
#   RKTIO_ERROR_LTPS_NOT_FOUND,
#   RKTIO_ERROR_LTPS_REMOVED, /* indicates success, instead of failure */
#   RKTIO_ERROR_CONNECT_TRYING_NEXT, /* indicates that failure is not (yet) premanent */
#   RKTIO_ERROR_ACCEPT_NOT_READY,
#   RKTIO_ERROR_HOST_AND_PORT_BOTH_UNSPECIFIED,
#   RKTIO_ERROR_INFO_TRY_AGAIN, /* for UDP */
#   RKTIO_ERROR_TRY_AGAIN, /* for UDP */
#   RKTIO_ERROR_TRY_AGAIN_WITH_IPV4, /* for TCP listen */
#   RKTIO_ERROR_TIME_OUT_OF_RANGE,
#   RKTIO_ERROR_NO_SUCH_ENVVAR,
#   RKTIO_ERROR_SHELL_EXECUTE_FAILED,
#   RKTIO_ERROR_CONVERT_NOT_ENOUGH_SPACE,
#   RKTIO_ERROR_CONVERT_BAD_SEQUENCE,
#   RKTIO_ERROR_CONVERT_PREMATURE_END,
#   RKTIO_ERROR_CONVERT_OTHER,
#   RKTIO_ERROR_DLL, /* use `rktio_dll_get_error` atomically to get error */
# };
class RKTIO_ERROR(_enum.IntEnum):
  RKTIO_ERROR_UNSUPPORTED = 1
  RKTIO_ERROR_INVALID_PATH = _enum.auto() # /* Windows path-decoding failure */
  RKTIO_ERROR_DOES_NOT_EXIST = _enum.auto() #
  RKTIO_ERROR_EXISTS = _enum.auto() #
  RKTIO_ERROR_ACCESS_DENIED = _enum.auto() #
  RKTIO_ERROR_LINK_FAILED = _enum.auto() #
  RKTIO_ERROR_NOT_A_LINK = _enum.auto() #
  RKTIO_ERROR_BAD_PERMISSION = _enum.auto() #
  RKTIO_ERROR_IS_A_DIRECTORY = _enum.auto() #
  RKTIO_ERROR_NOT_A_DIRECTORY = _enum.auto() #
  RKTIO_ERROR_UNSUPPORTED_TEXT_MODE = _enum.auto() #
  RKTIO_ERROR_CANNOT_FILE_POSITION = _enum.auto() #
  RKTIO_ERROR_NO_TILDE = _enum.auto() #
  RKTIO_ERROR_ILL_FORMED_USER = _enum.auto() #
  RKTIO_ERROR_UNKNOWN_USER = _enum.auto() #
  RKTIO_ERROR_INIT_FAILED = _enum.auto() #
  RKTIO_ERROR_LTPS_NOT_FOUND = _enum.auto() #
  RKTIO_ERROR_LTPS_REMOVED = _enum.auto() # /* indicates success = _enum.auto() # instead of failure */
  RKTIO_ERROR_CONNECT_TRYING_NEXT = _enum.auto() # /* indicates that failure is not (yet) premanent */
  RKTIO_ERROR_ACCEPT_NOT_READY = _enum.auto() #
  RKTIO_ERROR_HOST_AND_PORT_BOTH_UNSPECIFIED = _enum.auto() #
  RKTIO_ERROR_INFO_TRY_AGAIN = _enum.auto() # /* for UDP */
  RKTIO_ERROR_TRY_AGAIN = _enum.auto() # /* for UDP */
  RKTIO_ERROR_TRY_AGAIN_WITH_IPV4 = _enum.auto() # /* for TCP listen */
  RKTIO_ERROR_TIME_OUT_OF_RANGE = _enum.auto() #
  RKTIO_ERROR_NO_SUCH_ENVVAR = _enum.auto() #
  RKTIO_ERROR_SHELL_EXECUTE_FAILED = _enum.auto() #
  RKTIO_ERROR_CONVERT_NOT_ENOUGH_SPACE = _enum.auto() #
  RKTIO_ERROR_CONVERT_BAD_SEQUENCE = _enum.auto() #
  RKTIO_ERROR_CONVERT_PREMATURE_END = _enum.auto() #
  RKTIO_ERROR_CONVERT_OTHER = _enum.auto() #
  RKTIO_ERROR_DLL = _enum.auto() # /* use `rktio_dll_get_error` atomically to get error */

RKTIO_ERROR_UNSUPPORTED = RKTIO_ERROR.RKTIO_ERROR_UNSUPPORTED
RKTIO_ERROR_INVALID_PATH = RKTIO_ERROR.RKTIO_ERROR_INVALID_PATH
RKTIO_ERROR_DOES_NOT_EXIST = RKTIO_ERROR.RKTIO_ERROR_DOES_NOT_EXIST
RKTIO_ERROR_EXISTS = RKTIO_ERROR.RKTIO_ERROR_EXISTS
RKTIO_ERROR_ACCESS_DENIED = RKTIO_ERROR.RKTIO_ERROR_ACCESS_DENIED
RKTIO_ERROR_LINK_FAILED = RKTIO_ERROR.RKTIO_ERROR_LINK_FAILED
RKTIO_ERROR_NOT_A_LINK = RKTIO_ERROR.RKTIO_ERROR_NOT_A_LINK
RKTIO_ERROR_BAD_PERMISSION = RKTIO_ERROR.RKTIO_ERROR_BAD_PERMISSION
RKTIO_ERROR_IS_A_DIRECTORY = RKTIO_ERROR.RKTIO_ERROR_IS_A_DIRECTORY
RKTIO_ERROR_NOT_A_DIRECTORY = RKTIO_ERROR.RKTIO_ERROR_NOT_A_DIRECTORY
RKTIO_ERROR_UNSUPPORTED_TEXT_MODE = RKTIO_ERROR.RKTIO_ERROR_UNSUPPORTED_TEXT_MODE
RKTIO_ERROR_CANNOT_FILE_POSITION = RKTIO_ERROR.RKTIO_ERROR_CANNOT_FILE_POSITION
RKTIO_ERROR_NO_TILDE = RKTIO_ERROR.RKTIO_ERROR_NO_TILDE
RKTIO_ERROR_ILL_FORMED_USER = RKTIO_ERROR.RKTIO_ERROR_ILL_FORMED_USER
RKTIO_ERROR_UNKNOWN_USER = RKTIO_ERROR.RKTIO_ERROR_UNKNOWN_USER
RKTIO_ERROR_INIT_FAILED = RKTIO_ERROR.RKTIO_ERROR_INIT_FAILED
RKTIO_ERROR_LTPS_NOT_FOUND = RKTIO_ERROR.RKTIO_ERROR_LTPS_NOT_FOUND
RKTIO_ERROR_LTPS_REMOVED = RKTIO_ERROR.RKTIO_ERROR_LTPS_REMOVED
RKTIO_ERROR_CONNECT_TRYING_NEXT = RKTIO_ERROR.RKTIO_ERROR_CONNECT_TRYING_NEXT
RKTIO_ERROR_ACCEPT_NOT_READY = RKTIO_ERROR.RKTIO_ERROR_ACCEPT_NOT_READY
RKTIO_ERROR_HOST_AND_PORT_BOTH_UNSPECIFIED = RKTIO_ERROR.RKTIO_ERROR_HOST_AND_PORT_BOTH_UNSPECIFIED
RKTIO_ERROR_INFO_TRY_AGAIN = RKTIO_ERROR.RKTIO_ERROR_INFO_TRY_AGAIN
RKTIO_ERROR_TRY_AGAIN = RKTIO_ERROR.RKTIO_ERROR_TRY_AGAIN
RKTIO_ERROR_TRY_AGAIN_WITH_IPV4 = RKTIO_ERROR.RKTIO_ERROR_TRY_AGAIN_WITH_IPV4
RKTIO_ERROR_TIME_OUT_OF_RANGE = RKTIO_ERROR.RKTIO_ERROR_TIME_OUT_OF_RANGE
RKTIO_ERROR_NO_SUCH_ENVVAR = RKTIO_ERROR.RKTIO_ERROR_NO_SUCH_ENVVAR
RKTIO_ERROR_SHELL_EXECUTE_FAILED = RKTIO_ERROR.RKTIO_ERROR_SHELL_EXECUTE_FAILED
RKTIO_ERROR_CONVERT_NOT_ENOUGH_SPACE = RKTIO_ERROR.RKTIO_ERROR_CONVERT_NOT_ENOUGH_SPACE
RKTIO_ERROR_CONVERT_BAD_SEQUENCE = RKTIO_ERROR.RKTIO_ERROR_CONVERT_BAD_SEQUENCE
RKTIO_ERROR_CONVERT_PREMATURE_END = RKTIO_ERROR.RKTIO_ERROR_CONVERT_PREMATURE_END
RKTIO_ERROR_CONVERT_OTHER = RKTIO_ERROR.RKTIO_ERROR_CONVERT_OTHER
RKTIO_ERROR_DLL = RKTIO_ERROR.RKTIO_ERROR_DLL

# RKTIO_EXTERN_NOERR int rktio_get_last_error(rktio_t *rktio);
capi_rktio_get_last_error = librktio.rktio_get_last_error
capi_rktio_get_last_error.argtypes = [rktio_p]
capi_rktio_get_last_error.restype = int_t
def rktio_get_last_error(rktio: rktio_p):
  if err := capi_call("rktio_get_last_error", check_rktio_p(rktio)):
    kind = rktio_get_last_error_kind(rktio)
    if kind == RKTIO_ERROR_KIND_POSIX:
      return POSIX_ERRNO(err)
    return RKTIO_ERROR(err)

# RKTIO_EXTERN_NOERR int rktio_get_last_error_step(rktio_t *rktio);
# /* Some operations report further information about the step that
#    failed. The meaning of a step number is operation-specific. */
capi_rktio_get_last_error_step = librktio.rktio_get_last_error_step
capi_rktio_get_last_error_step.argtypes = [rktio_p]
capi_rktio_get_last_error_step.restype = int_t
def rktio_get_last_error_step(rktio) -> int:
  """Some operations report further information about the step that
  failed. The meaning of a step number is operation-specific."""
  out = capi_call("rktio_get_last_error_step", check_rktio_p(rktio))
  return out

# RKTIO_EXTERN void rktio_set_last_error(rktio_t *rktio, int kind, int errid);
capi_rktio_set_last_error = librktio.rktio_set_last_error
capi_rktio_set_last_error.argtypes = [rktio_p, int_t, int_t]
capi_rktio_set_last_error.restype = None
def rktio_set_last_error(rktio, kind: RKTIO_ERROR_KIND, errid: int):
  #out = capi_call("rktio_set_last_error", check_rktio_p(rktio), int(RKTIO_ERROR_KIND(kind)), int(RKTIO_ERROR(errid)))
  out = capi_call("rktio_set_last_error", check_rktio_p(rktio), int(kind), int(errid))
  return out
# RKTIO_EXTERN void rktio_set_last_error_step(rktio_t *rktio, int step);
capi_rktio_set_last_error_step = librktio.rktio_set_last_error_step
capi_rktio_set_last_error_step.argtypes = [rktio_p, int_t]
capi_rktio_set_last_error_step.restype = None
def rktio_set_last_error_step(rktio, step: int):
  out = capi_call("rktio_set_last_error_step", check_rktio_p(rktio), step)
  return out
# /* In case you need to save and restore error information. */

def rktio_peek_error(rktio):
  if errid := rktio_get_last_error(rktio):
    kind = rktio_get_last_error_kind(rktio)
    step = rktio_get_last_error_step(rktio)
    return errid, kind, step

def rktio_clear_error(rktio):
  it = rktio_peek_error(rktio)
  rktio_set_last_error(rktio, 0, 0)
  rktio_set_last_error_step(rktio, 0)
  return it

# RKTIO_EXTERN void rktio_remap_last_error(rktio_t *rktio);
# /* In a few cases, rktio substitutes a `RKTIO_ERROR_KIND_RACKET` error
#    for an OS-supplied error. This function can sometimes undo the
#    substitition, modifying the current error and kind. */
capi_rktio_remap_last_error = librktio.rktio_remap_last_error
capi_rktio_remap_last_error.argtypes = [rktio_p]
capi_rktio_remap_last_error.restype = None
def rktio_remap_last_error(rktio):
  """In a few cases, rktio substitutes a `RKTIO_ERROR_KIND_RACKET` error
  for an OS-supplied error. This function can sometimes undo the
  substitition, modifying the current error and kind."""
  out = capi_call("rktio_remap_last_error", check_rktio_p(rktio))
  return out

# RKTIO_EXTERN_NOERR const char *rktio_get_last_error_string(rktio_t *rktio);
capi_rktio_get_last_error_string = librktio.rktio_get_last_error_string
capi_rktio_get_last_error_string.argtypes = [rktio_p]
capi_rktio_get_last_error_string.restype = void_p
def rktio_get_last_error_string(rktio: rktio_p):
  out = capi_call("rktio_get_last_error_string", check_rktio_p(rktio))
  return maybeutf8(out)


# RKTIO_EXTERN_NOERR const char *rktio_get_error_string(rktio_t *rktio, int kind, int errid);
capi_rktio_get_error_string = librktio.rktio_get_error_string
capi_rktio_get_error_string.argtypes = [rktio_p]
capi_rktio_get_error_string.restype = void_p
def rktio_get_error_string(rktio, kind: RKTIO_ERROR_KIND, errid: RKTIO_ERROR):
  out = capi_call("rktio_get_error_string", check_rktio_p(rktio), kind, errid) #int(RKTIO_ERROR_KIND(kind)), int(RKTIO_ERROR(errid)))
  return maybeutf8(out)
# /* The returned string for `rktio_...error_string` should not be
#    deallocated, but it only lasts reliably until the next call to
#    either of the functions. */

# /*************************************************/


import platform
from socket import (
    inet_ntop,
    AF_INET,
    AF_INET6,
)

libc = _c.CDLL(None)


if True:

  class c_sockaddr_in4(_c.Structure):
      _fields_ = [
          ('sin_family', _c.c_uint16),
          ('sin_port', _c.c_uint16),
          ('sin_addr', _c.c_ubyte * 4),
      ]


  class c_sockaddr_in6(_c.Structure):
      _fields_ = [
          ('sin_family', _c.c_uint16),
          ('sin_port', _c.c_uint16),
          ('sin_flowinfo', _c.c_uint32),
          ('sin_addr', _c.c_ubyte * 16),
          ('sin_scope_id', _c.c_uint32),
      ]

  class c_sockaddr_in(_c.Union):
      _fields_ = [
          ('ai_addr4', c_sockaddr_in4),
          ('ai_addr6', c_sockaddr_in6),
      ]
      @property
      def u(self):
        return self

else:

  class c_sockaddr_in4(_c.Structure):
      _fields_ = [
          # ('sin_family', _c.c_uint16),
          ('sin_port', _c.c_uint16),
          ('sin_addr', _c.c_ubyte * 4),
      ]


  class c_sockaddr_in6(_c.Structure):
      _fields_ = [
          # ('sin_family', _c.c_uint16),
          ('sin_port', _c.c_uint16),
          ('sin_flowinfo', _c.c_uint32),
          ('sin_addr', _c.c_ubyte * 16),
          ('sin_scope_id', _c.c_uint32),
      ]

  class c_sockaddr_in_body(_c.Union):
      _fields_ = [
          ('ai_addr4', c_sockaddr_in4),
          ('ai_addr6', c_sockaddr_in6),
      ]

  class c_sockaddr_in(_c.Structure):
      _fields_ = [
          ('sin_family', _c.c_uint16),
          ('u', c_sockaddr_in_body),
      ]

class c_sockaddr(_c.Structure):
    _fields_ = [
        ('sin_size', _c.c_uint8),
        ('sin_family_', _c.c_int8),
        ('sin_addr_', _c.c_char * 0),
    ]
    @property
    def sin_family(self):
      return socket.AddressFamily(self.sin_family_)

    @property
    def sin_addr_raw(self):
      addr = _c.addressof(self) + c_sockaddr.sin_addr_.offset
      addrlen = max(0, self.sin_size - 2)
      return dynamic_array(_c.c_char, addr, addrlen)

    @property
    def sin_addr(self):
      addr = _c.addressof(self) + c_sockaddr.sin_addr_.offset
      addrlen = max(0, self.sin_size - 2)
      family = self.sin_family
      if family == socket.AddressFamily.AF_UNIX:
        return dynamic_array(_c.c_char, addr, addrlen)
      elif family == socket.AddressFamily.AF_INET:
        return dynamic_array(c_sockaddr_in4, addr, 1)[0]
        # return _c.POINTER(c_sockaddr_in4).from_address(addr)
      elif family == socket.AddressFamily.AF_INET6:
        return dynamic_array(c_sockaddr_in6, addr, 1)[0]
        # return _c.POINTER(c_sockaddr_in6).from_address(addr)
      else:
        raise NotImplementedError(family)

    def __repr__(self):
      return f"c_sockaddr(sin_size={self.sin_size}, sin_family={self.sin_family.name}, sin_addr={_repr(self.sin_addr)})"


def _repr(x):
  if hasattr(x, 'raw'):
    return repr(x.raw)
  return repr(x)


class c_addrinfo(_c.Structure):
    pass


c_addrinfo._fields_ = [
    ('ai_flags', _c.c_uint32),
    ('ai_family', _c.c_uint32),
    ('ai_socktype', _c.c_uint32),
    ('ai_protocol', _c.c_uint32),
    ('ai_addrlen', _c.c_uint32),
] + ([
    ('ai_canonname', _c.c_char_p),
    ('ai_addr', _c.POINTER(c_sockaddr_in)),
] if platform.system() == 'Darwin' else [
    ('ai_addr', _c.POINTER(c_sockaddr_in)),
    ('ai_canonname', _c.c_char_p),
]) + [
    ('ai_next', _c.POINTER(c_addrinfo)),
]

c_addrinfo_p = _c.POINTER(c_addrinfo)

address_field_names = {
    AF_INET: 'ai_addr4',
    AF_INET6: 'ai_addr6',
}

def getaddrinfo(host, port, family=socket.AddressFamily.AF_INET.value, type=socket.SocketKind.SOCK_STREAM.value, proto=0, flags=0):
    result = c_addrinfo_p()
    hints = c_addrinfo()

    hints.flags = flags
    hints.ai_family = family
    hints.ai_socktype = type
    hints.proto = proto

    result = c_addrinfo_p()
    error = libc.getaddrinfo(
        _c.c_char_p(host),
        _c.c_char_p(port) if port is not None else None,
        _c.byref(hints),
        _c.byref(result),
    )
    if error:
        raise Exception(error)

    result_addrinfo = result.contents
    family = socket.AddressFamily(result_addrinfo.ai_family)
    address_field_name = address_field_names[family]
    address_field = getattr(result_addrinfo.ai_addr.contents.u, address_field_name)
    address_raw = address_field.sin_addr

    address = inet_ntop(family, address_raw)
    libc.freeaddrinfo(result)

    return (family, address)


def check_errno(out, *rest):
  if out != 0:
    code = _c.get_errno()
    msg = _os.strerror(code)
    err = OSError(f'{code}: {msg}', (out, *rest))
    err.errno = code
    err.strerror = msg
    raise err
  return out

socklen_t = intptr_t
socklen_p = _c.POINTER(socklen_t)

capi_getsockname = libc.getsockname
#capi_getsockname.argtypes = [int_t, _c.POINTER(c_sockaddr_in), _c.POINTER(socklen_t)]
capi_getsockname.argtypes = [int_t, void_p, _c.POINTER(socklen_t)]
capi_getsockname.restype = int_t
capi_getsockname.errcheck = check_errno
def getsockname(sockfd):
  fd = check_int(sockfd)
  n = socklen_t()
  capi_call("capi_getsockname", fd, None, n)
  buf = (_c.c_char * n.value)()
  capi_call("capi_getsockname", fd, buf, n)
  addr = c_sockaddr()
  _c.resize(addr, n.value)
  capi_call("capi_getsockname", fd, _c.pointer(addr), n)
  return addr




# /*************************************************/





# rktio_addrinfo_t *lookup_loop(rktio_t *rktio,
#                               const char *hostname, int portno,
#                               int family, int passive, int tcp)
# {
def lookup_loop(rktio, hostname: Optional[str], portno: int, family: int = -1, passive: bool = True, tcp: bool = True):
  # rktio_addrinfo_lookup_t *lookup;
  # rktio_addrinfo_t *addr;

  lookup = rktio_start_addrinfo_lookup(rktio, hostname, portno, family, passive, tcp);
  # check_valid(lookup);

  # while (rktio_poll_addrinfo_lookup_ready(rktio, lookup) == RKTIO_POLL_NOT_READY) {
  while rktio_poll_addrinfo_lookup_ready(rktio, lookup) == RKTIO_POLL_NOT_READY:
    # rktio_poll_set_t *ps;
    # ps = rktio_make_poll_set(rktio);
    # check_valid(ps);
    ps = rktio_make_poll_set(rktio)

    # rktio_poll_add_addrinfo_lookup(rktio, lookup, ps);
    # rktio_sleep(rktio, 0, ps, NULL);
    # rktio_poll_set_forget(rktio, ps);

    rktio_poll_add_addrinfo_lookup(rktio, lookup, ps)
    rktio_sleep(rktio, 0, ps, NULL)
    rktio_poll_set_forget(rktio, ps)
    del ps
  # }
  
  # check_valid(rktio_poll_addrinfo_lookup_ready(rktio, lookup) == RKTIO_POLL_READY);
  check_valid(rktio, rktio_poll_addrinfo_lookup_ready(rktio, lookup) == RKTIO_POLL_READY)

  # addr = rktio_addrinfo_lookup_get(rktio, lookup);
  # check_valid(addr);

  addr = rktio_addrinfo_lookup_get(rktio, lookup);

  return addr;
# }


def wait_read(rktio, rfd):
  while rktio_poll_read_ready(rktio, rfd) == RKTIO_POLL_NOT_READY:
    ps = rktio_make_poll_set(rktio)
    try:
      rktio_poll_add(rktio, rfd, ps, RKTIO_POLL_READ);
      rktio_sleep(rktio, -1, ps, NULL);
    finally:
      rktio_poll_set_forget(rktio, ps)

# void check_ltps_write_ready(rktio_t *rktio, rktio_ltps_t *lt, rktio_ltps_handle_t *h2)
# {
def check_ltps_write_ready(rktio, lt, h2):
  # rktio_ltps_handle_t *hy;

  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  # check_expected_racket_error(!hy, RKTIO_ERROR_LTPS_NOT_FOUND);
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hy = rktio_ltps_get_signaled_handle(rktio, lt)

  # check_valid(rktio_ltps_poll(rktio, lt));
  check_valid(rktio, rktio_ltps_poll(rktio, lt))
  
  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  # check_valid(hy == h2);
  # rktio_free(hy);
  hy = rktio_ltps_get_signaled_handle(rktio, lt)
  check_valid(rktio, hy == h2)
  hy = rktio_free(hy)
  
  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  # check_expected_racket_error(!hy, RKTIO_ERROR_LTPS_NOT_FOUND);
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hy = rktio_ltps_get_signaled_handle(rktio, lt)
# }


# void check_ltps_read_ready(rktio_t *rktio, rktio_ltps_t *lt, rktio_ltps_handle_t *h1)
# {
def check_ltps_read_ready(rktio, lt, h1):
  # rktio_ltps_handle_t *hy;

  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  # check_expected_racket_error(!hy, RKTIO_ERROR_LTPS_NOT_FOUND);
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hy = rktio_ltps_get_signaled_handle(rktio, lt)
  
  # check_valid(rktio_ltps_poll(rktio, lt));
  check_valid(rktio, rktio_ltps_poll(rktio, lt))
  
  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  hy = rktio_ltps_get_signaled_handle(rktio, lt)
  # check_valid(hy == h1);
  check_valid(rktio, hy == h1)
  # rktio_free(hy);
  hy = rktio_free(hy)
  
  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  # check_expected_racket_error(!hy, RKTIO_ERROR_LTPS_NOT_FOUND);
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hy = rktio_ltps_get_signaled_handle(rktio, lt)
# }

# void check_ltps_read_and_write_ready(rktio_t *rktio, rktio_ltps_t *lt, rktio_ltps_handle_t *h1, rktio_ltps_handle_t *h2)
# {
def check_ltps_read_and_write_ready(rktio, lt, h1, h2):
  # rktio_ltps_handle_t *hy;

  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  # check_expected_racket_error(!hy, RKTIO_ERROR_LTPS_NOT_FOUND);
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hy = rktio_ltps_get_signaled_handle(rktio, lt)

  # check_valid(rktio_ltps_poll(rktio, lt));
  check_valid(rktio, rktio_ltps_poll(rktio, lt))
  
  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  hy = rktio_ltps_get_signaled_handle(rktio, lt)
  # if (hy == h1) {
  if hy == h1:
    # rktio_free(hy);
    hy = rktio_free(hy)
    # hy = rktio_ltps_get_signaled_handle(rktio, lt);
    hy = rktio_ltps_get_signaled_handle(rktio, lt)
    # check_valid(hy == h2);
    check_valid(rktio, hy == h2)
  # } else {
  else:
    # check_valid(hy == h2);
    check_valid(rktio, hy == h2)
    # rktio_free(hy);
    hy = rktio_free(hy)
    # hy = rktio_ltps_get_signaled_handle(rktio, lt);
    hy = rktio_ltps_get_signaled_handle(rktio, lt)
    # check_valid(hy == h1);
    check_valid(rktio, hy == h1)
  # }
  # rktio_free(hy);
  hy = rktio_free(hy)

  # hy = rktio_ltps_get_signaled_handle(rktio, lt);
  # check_expected_racket_error(!hy, RKTIO_ERROR_LTPS_NOT_FOUND);
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hy = rktio_ltps_get_signaled_handle(rktio, lt)
# }



import contextlib

@contextlib.contextmanager
def with_expected_racket_error(rktio, code: RKTIO_ERROR, required=False):
  try:
    yield
  except RktioException as e:
    exn = e
    if code != exn.code:
      raise
  if it := rktio_clear_error(rktio):
    errid, kind, step = it
    if errid != code:
      raise RuntimeError("Unexpected error", (errid, kind, step))
  elif required:
    raise RuntimeError("Expected error", code)

def try_check_ltps(rktio,
                   fd, # read mode
                   fd2): # write mode
  lt = rktio_ltps_open(rktio)

  # Add read handle for fd1
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    try:
      h1 = rktio_ltps_add(rktio, lt, fd, RKTIO_LTPS_CHECK_READ)
    except RktioException as e:
      exn = e
      if exn.code == RKTIO_ERROR_UNSUPPORTED:
        release(lt)
        return None, None, None
      raise
  #check_expected_racket_error(!h1, RKTIO_ERROR_LTPS_NOT_FOUND)
  breakpoint()

  h1 = rktio_ltps_add(rktio, lt, fd, RKTIO_LTPS_CREATE_READ)
  check_valid(rktio, h1)
  hx = rktio_ltps_add(rktio, lt, fd, RKTIO_LTPS_CREATE_READ)
  check_valid(rktio, hx == h1)
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hx = rktio_ltps_add(rktio, lt, fd, RKTIO_LTPS_CHECK_WRITE)
    #check_expected_racket_error(!hx, RKTIO_ERROR_LTPS_NOT_FOUND)

  # Add write handle for fd2
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    h2 = rktio_ltps_add(rktio, lt, fd2, RKTIO_LTPS_CHECK_READ)
    # check_expected_racket_error(!h2, RKTIO_ERROR_LTPS_NOT_FOUND)
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    h2 = rktio_ltps_add(rktio, lt, fd2, RKTIO_LTPS_CHECK_WRITE)
    # check_expected_racket_error(!h2, RKTIO_ERROR_LTPS_NOT_FOUND)
  h2 = rktio_ltps_add(rktio, lt, fd2, RKTIO_LTPS_CREATE_WRITE)
  check_valid(rktio, h2)
  hx = rktio_ltps_add(rktio, lt, fd2, RKTIO_LTPS_CREATE_READ)
  check_valid(rktio, hx)

  # Removing `fd2` should signal the handles `h2` and `hx`
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_REMOVED):
    hy = rktio_ltps_add(rktio, lt, fd2, RKTIO_LTPS_REMOVE)
    check_valid(rktio, (hy == h2) or (hy == hx))
    hy = rktio_free(hy)
  hy = rktio_ltps_get_signaled_handle(rktio, lt)
  check_valid(rktio, (hy == h2) or (hy == hx))
  hy = rktio_free(hy)
  with with_expected_racket_error(rktio, RKTIO_ERROR_LTPS_NOT_FOUND):
    hy = rktio_ltps_get_signaled_handle(rktio, lt)
  # Add write handle for fd2 again:
  h2 = rktio_ltps_add(rktio, lt, fd2, RKTIO_LTPS_CREATE_WRITE)
  check_valid(rktio, h2)

  return lt, h1, h2

# /* On Unix, we expect writing to a pipe to make the bytes
#    immediately available. On Windows, we expect a delay. */
#ifdef RKTIO_SYSTEM_UNIX
# define PIPE_IMMEDIATELY_READY 1
#else
# define PIPE_IMMEDIATELY_READY 0
#endif
if _os.name == 'nt':
  PIPE_IMMEDIATELY_READY = 0
else:
  PIPE_IMMEDIATELY_READY = 1


# static void check_read_write_pair(rktio_t *rktio, rktio_fd_t *fd, rktio_fd_t *fd2, int immediate_available)
# {
def check_read_write_pair(rktio, fd, fd2, immediate_available=PIPE_IMMEDIATELY_READY, *, close=True, count=256):
  #rktio_ltps_t *lt;
  #rktio_ltps_handle_t *h1, *h2;
  #intptr_t amt;
  #char buffer[256];

  #lt = try_check_ltps(rktio, fd, fd2, &h1, &h2);
  lt, h1, h2 = try_check_ltps(rktio, fd, fd2)

  #/* We expect `lt` to work everywhere exception Windows and with kqueue on non-sockets: */
  ##if !defined(RKTIO_SYSTEM_WINDOWS)
  ## if !defined(HAVE_KQUEUE_SYSCALL)
    #check_valid(lt);
  ## else
    #if (rktio_fd_is_socket(rktio, fd) && rktio_fd_is_socket(rktio, fd2))
    #  check_valid(lt);
  ## endif
  ##endif

  #/* fd2 can write, fd cannot yet read */
  #check_valid(!rktio_poll_read_ready(rktio, fd));
  check_valid(rktio, not rktio_poll_read_ready(rktio, fd))
  #if (lt)
  #  check_ltps_write_ready(rktio, lt, h2);
  if lt:
    check_ltps_write_ready(rktio, lt, h2)

  #/* Round-trip data through pipe: */
  #if (rktio_fd_is_udp(rktio, fd2)) {
  if rktio_fd_is_udp(rktio, fd2):
    # amt = rktio_udp_sendto(rktio, fd2, NULL, "hola\n", 5);
    amt = rktio_udp_sendto(rktio, fd2, NULL, b"hola\n")
  #} else
  else:
    # amt = rktio_write(rktio, fd2, "hola\n", 5);
    amt = rktio_write(rktio, fd2, b"hola\n")
  #check_valid(amt == 5);
  check_valid(rktio, amt == 5)
  
  #if (!immediate_available) {
  #  /* Wait for read to be ready; should not block for long */
  #  wait_read(rktio, fd);
  #}
  if not immediate_available:
    # Wait for read to be ready; should not block for long
    wait_read(rktio, fd)

  #check_valid(rktio_poll_read_ready(rktio, fd) == RKTIO_POLL_READY);
  check_valid(rktio, rktio_poll_read_ready(rktio, fd) == RKTIO_POLL_READY)
  #if (lt) {
  #  check_ltps_read_ready(rktio, lt, h1);
  #  rktio_ltps_close(rktio, lt);
  #}
  if lt:
    check_ltps_read_ready(rktio, lt, h1)
    lt = rktio_ltps_close(rktio, lt)


  #if (rktio_fd_is_udp(rktio, fd)) {
  if rktio_fd_is_udp(rktio, fd):
    # rktio_length_and_addrinfo_t *r;
    # do {
    #   r = rktio_udp_recvfrom(rktio, fd, buffer, sizeof(buffer));
    # } while (!r
    #          && (rktio_get_last_error_kind(rktio) == RKTIO_ERROR_KIND_RACKET)
    #          && (rktio_get_last_error(rktio) == RKTIO_ERROR_INFO_TRY_AGAIN));
    # check_valid(r);
    # amt = r->len;
    # free(r->address[0]);
    # free(r->address[1]);
    # free(r->address);
    # free(r);
    raise NotImplementedError
  #} else
  else:
    # amt = rktio_read(rktio, fd, buffer, sizeof(buffer));
    buffer = rktio_read(rktio, fd, count)
  #check_valid(amt == 5);
  check_valid(rktio, len(buffer) == 5)
  #check_valid(!strncmp(buffer, "hola\n", 5));
  check_valid(rktio, buffer == b"hola\n")
  #check_valid(!rktio_poll_read_ready(rktio, fd));
  check_valid(rktio, not rktio_poll_read_ready(rktio, fd))

  if close:
    #/* Close pipe ends: */
    #check_valid(rktio_close(rktio, fd2));
    check_valid(rktio, rktio_close(rktio, fd2))

  #if (!rktio_fd_is_udp(rktio, fd)) {
  if not rktio_fd_is_udp(rktio, fd):
   # if (!immediate_available) {
   if not immediate_available:
     # /* Wait for EOF to be ready; should not block for long */
     # wait_read(rktio, fd);
     wait_read(rktio, fd)
   # }
    
   # amt = rktio_read(rktio, fd, buffer, sizeof(buffer));
   buffer = rktio_read(rktio, fd, count)
   # check_valid(amt == RKTIO_READ_EOF);
   check_valid(rktio, buffer is None)
  #}
  
  if close:
    #check_valid(rktio_close(rktio, fd));
    check_valid(rktio, rktio_close(rktio, fd))



def pipe_test(rktio):

  # pipe_fds = rktio_make_pipe(rktio, 0);
  # check_valid(pipe_fds);

  # fd = pipe_fds[0];
  # check_valid(fd);
  # check_valid(!rktio_poll_read_ready(rktio, fd));
  # fd2 = pipe_fds[1];
  # check_valid(fd2);
  # check_valid(!rktio_poll_read_ready(rktio, fd));

  # free(pipe_fds);

  fd, fd2 = rktio_make_pipe(rktio, 0)
  check_valid(rktio, fd)
  check_valid(rktio, not rktio_poll_read_ready(rktio, fd))
  check_valid(rktio, fd2)
  check_valid(rktio, not rktio_poll_read_ready(rktio, fd2))

  check_read_write_pair(rktio, fd, fd2, PIPE_IMMEDIATELY_READY)
  

