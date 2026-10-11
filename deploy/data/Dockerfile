FROM postgres:18.6-alpine
# Keep the upstream entrypoint and physical volume layout; add only a bounded
# owner-store reconciler before reporting this existing container healthy.
COPY deploy/data/owner-bootstrap.psql /usr/local/share/briareus/owner-bootstrap.psql
COPY deploy/data/postgres-entrypoint.sh /usr/local/bin/briareus-postgres-entrypoint
RUN chmod 0555 /usr/local/bin/briareus-postgres-entrypoint
ENTRYPOINT ["/usr/local/bin/briareus-postgres-entrypoint"]
CMD ["postgres"]
