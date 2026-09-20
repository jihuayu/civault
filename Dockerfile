FROM node:24-alpine AS console
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.8-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=console /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/civault-server ./cmd/civault-server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/civault ./cmd/civault

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 civault && adduser -D -u 10001 -G civault civault \
 && mkdir /data && chown civault:civault /data && chmod 700 /data
COPY --from=build /out/ /usr/local/bin/
COPY docs/THIRD_PARTY_*_NOTICES.txt /usr/share/licenses/civault/
COPY LICENSE /usr/share/licenses/civault/LICENSE
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["civault-server"]
