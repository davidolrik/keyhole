FROM busybox:musl AS tmp
RUN mkdir -p /tmp && chmod 1777 /tmp

FROM scratch
COPY --from=tmp /tmp /tmp
COPY keyhole /keyhole
ENTRYPOINT ["/keyhole", "serve"]
