FROM golang:1.23.3-alpine AS builder

WORKDIR /opt

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go build -o /opt/cmd/main /opt/cmd/main.go

EXPOSE 8080

CMD [ "/opt/cmd/main" ]