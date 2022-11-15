FROM golang:1.18 AS build

RUN mkdir /build

WORKDIR /build

COPY ./ ./

RUN go run mage.go binary

RUN useradd -u 1001 app \
 && mkdir /config \
 && chown app:root /config

FROM scratch

COPY --from=build /build/vault-automation-client /bin/vault-automation-client
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /config /

ENV PATH=/bin:$PATH

ENTRYPOINT ["vault-automation-client"]

USER 1001