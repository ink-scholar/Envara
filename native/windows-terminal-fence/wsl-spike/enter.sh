#!/bin/sh
# What the Envara terminal runs inside ConPTY: join the environment namespace,
# drop to the unprivileged account, with an environment Envara fully controls.
NS=${NS:-envpty}; SU=$(command -v su-exec)
exec ip netns exec "$NS" env -i HOME=/home/env USER=env LOGNAME=env SHELL=/bin/bash \
  TERM=xterm-256color COLORTERM=truecolor LANG=C.UTF-8 \
  PATH=/opt/spike/bin:/home/env/.local/bin:/usr/local/bin:/usr/bin:/bin \
  BROWSER=/opt/spike/bin/open-url \
  "$SU" env /bin/bash --login
