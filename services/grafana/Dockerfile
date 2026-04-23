FROM grafana/grafana:latest

USER root
COPY docker-entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh
USER grafana

ENTRYPOINT ["/custom-entrypoint.sh"]
