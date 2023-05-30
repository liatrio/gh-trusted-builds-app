FROM golang:1.20-alpine as builder

WORKDIR /app

COPY main.go go.mod go.sum ./
RUN go build -o server ./

###
FROM scratch

WORKDIR /app

COPY --from=builder /app/server .

ENTRYPOINT ["/app/server"]
