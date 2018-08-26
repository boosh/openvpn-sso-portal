FROM golang:1.11-rc AS build

WORKDIR /app
COPY . . 
RUN go build


FROM debian

RUN adduser --disabled-password --gecos "" app
USER app
WORKDIR /home/app

COPY --from=build /app/openvpn-sso-portal .
COPY --from=build /app/assets ./assets

ENTRYPOINT ["./openvpn-sso-portal"]
CMD ["--config", "/home/app/config/portal.yml"]
