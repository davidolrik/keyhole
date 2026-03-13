FROM scratch
COPY keyhole /keyhole
ENTRYPOINT ["/keyhole", "serve"]
