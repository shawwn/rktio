import rktio as rio
import os
import socket

print("pid:", os.getpid())

_c = rio._c
r = rio.rktio_init()

rio.pipe_test(r)

def resolve(hostname, port):
  return rio.lookup_loop(r, hostname, port)

def listen(hostname, port, backlog: int, reuse: bool):
  addr = resolve(hostname, port)
  l = rio.rktio_listen(r, addr, backlog, reuse)
  rio.release(addr)
  #rio.rktio_addrinfo_free(r, addr)
  #del addr
  return l

def importfd(fd, init=True):
  if hasattr(fd, "fileno"):
    fd = fd.fileno()
  print("importing fd", fd, "init" if init else "")
  mode = rio.RKTIO_OPEN_SOCKET
  if init:
    mode |= rio.RKTIO_OPEN_INIT
  return rio.rktio_system_fd(r, fd, mode)
  

def accept(s):
  fd, _ = s.accept()
  return importfd(fd.detach())


server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
  os.unlink("/tmp/socket_test.s")
except OSError:
  pass
server.bind("/tmp/socket_test.s")
server.listen(10)
rfd = importfd(server)


l = rio.rktio_listener_alloc(server.fileno(), server.fileno())

l2 = listen(None, 4536, 5, 1)


#fd = rio.rktio_open(r, "foo.txt", rio.RKTIO_OPEN_READ | rio.RKTIO_OPEN_MUST_EXIST | rio.RKTIO_OPEN_TEXT)
#rio.rktio_close(r, fd)


#fd2 = rio.rktio_open(r, "out.txt", rio.RKTIO_OPEN_READ | rio.RKTIO_OPEN_MUST_EXIST | rio.RKTIO_OPEN_TEXT)

# rio.rktio_install_os_signal_handler(r)

it = None
i = 0
while True:
  break
  i += 1
  rio.rktio_wait_until_signal_received(r)
  prev, it = it, rio.rktio_poll_os_signal(r)
  print(f"signal {i}:", it)
  # if it == rio.RKTIO_OS_SIGNAL_TERM:
  #   break
  if it == rio.RKTIO_OS_SIGNAL_INT:
    if prev == rio.RKTIO_OS_SIGNAL_INT:
      break
    #print("(To exit, press Ctrl+C again or Ctrl+D or type .exit)")
    print("(To exit, press Ctrl+C again)")

rio.rktio_clear_error(r)

# rio.rktio_destroy(r)
os.exit(0)
