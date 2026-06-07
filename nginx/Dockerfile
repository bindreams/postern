# syntax=docker/dockerfile:1
FROM dhi.io/nginx:1-alpine3.23

# DHI nginx is distroless and does NOT honor the docker-library /docker-entrypoint.d/
# convention -- its entrypoint runs nginx directly. To add the templated render
# step (so DOMAIN comes from .env, not VCS edits) plus the periodic-reload loop
# we ship our own ENTRYPOINT.
#
# Note: this image has NO root user in /etc/passwd, so `USER root` + `RUN apk ...`
# is impossible. Modifying /etc/group at build time (e.g. to put nginx in
# gid 110 to read privkey.pem 0640) would require a multi-stage build that
# constructs /etc/group from scratch and COPYs it in. We instead make the
# privkey world-readable (provisioner writes 0644) -- the single-tenant trust
# boundary is "anyone with shell access in any container is already admin-
# equivalent", so 0644 is an acceptable degradation. See the install path in
# postern_provisioner.install for where this is enforced.

# Bring the source-tree configs in under /etc/nginx/templates/; the entrypoint
# renders *.tmpl files (substituting ${DOMAIN}) into /etc/nginx/ at start. The
# image's own /etc/nginx/{mime.types,fastcgi*,scgi*,uwsgi*,modules} remain
# untouched.
COPY etc/ /etc/nginx/templates/
COPY --chmod=755 render.sh /usr/local/bin/render.sh
COPY --chmod=755 nginx-entrypoint.sh /usr/local/bin/nginx-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/nginx-entrypoint.sh"]
