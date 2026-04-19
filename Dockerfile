FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN go build -o ids-agent .

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/ids-agent .
EXPOSE 8766
CMD ["./ids-agent"]
