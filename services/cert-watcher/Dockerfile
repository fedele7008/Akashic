FROM docker:cli
RUN apk add --no-cache inotify-tools bash
COPY watch.sh /watch.sh
RUN chmod +x /watch.sh
ENTRYPOINT ["/bin/bash", "/watch.sh"]
