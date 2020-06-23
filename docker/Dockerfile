FROM inomial.io/openjdk8-jre
ENV SERVICE=turnstile-audirectdebit-gw
ARG version
ENV APPLICATION_JAR "/opt/inomial.com/$SERVICE/$SERVICE-$version-all.jar"
RUN mkdir -p /opt/inomial.com/$SERVICE
RUN adduser -D -u 1000 $SERVICE
COPY $SERVICE-$version-all.jar /opt/inomial.com/$SERVICE
COPY entrypoint.sh /opt/inomial.com/
EXPOSE 8080
USER 1000
ENTRYPOINT [ "/opt/inomial.com/entrypoint.sh" ]

