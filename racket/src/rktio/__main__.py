import rktio as rio
import os

print("pid:", os.getpid())

_c = rio._c
r = rio.rktio_init()

rio.pipe_test(r)

fd = rio.rktio_open(r, "foo.txt", rio.RKTIO_OPEN_READ | rio.RKTIO_OPEN_MUST_EXIST | rio.RKTIO_OPEN_TEXT)
rio.rktio_close(r, fd)


#fd2 = rio.rktio_open(r, "out.txt", rio.RKTIO_OPEN_READ | rio.RKTIO_OPEN_MUST_EXIST | rio.RKTIO_OPEN_TEXT)

rio.rktio_install_os_signal_handler(r)

it = None
i = 0
while True:
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

# rio.rktio_destroy(r)
