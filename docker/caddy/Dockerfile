# Caddy for ph-reqKO, hardened for cap_drop: ALL.
#
# The stock caddy:2.8.4 image sets the file capability
# cap_net_bind_service=+ep on /usr/bin/caddy (so it can bind 443 as a
# non-root process). With cap_drop: ALL the container bounding set has no
# cap_net_bind_service, and execve() of a file whose file capabilities
# exceed the bounding set fails with "operation not permitted".
#
# Fix: strip the file capability at build time and let Caddy listen on
# the UNPRIVILEGED port 8443 inside the container; compose publishes host
# 443 -> container 8443. The container keeps cap_drop: ALL.
FROM caddy:2.8.4

RUN setcap -r /usr/bin/caddy
