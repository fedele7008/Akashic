FROM redis/redisinsight:latest

USER root
COPY docker-entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh
USER node

ENTRYPOINT ["/custom-entrypoint.sh"]
