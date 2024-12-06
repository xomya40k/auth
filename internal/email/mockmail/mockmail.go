package mockmail

import (
	"errors"
	"fmt"
	"log/slog"

	"auth/internal/config"
)

type Dialer struct {
	Host     string
	Port     int
	From     string
	Password string
	log      *slog.Logger
}

type Message struct {
	From    string
	To      string
	Subject string
	Body    string
}

type Email struct {
	Dialer Dialer
}

func New(config config.Email, log *slog.Logger) *Email {
	d := Dialer{config.Host, config.Port, config.From, config.Password, log}

	return &Email{Dialer: d}
}

func (email *Email) SendIpWarnig(to, ip string) error {
	const op = "email.mockmail.SendIpWarnig"

	message := Message{}
	message.From = email.Dialer.From
	message.To = to
	message.Subject = "New IP warning"
	message.Body = "IP: " + ip

	err := email.Dialer.Send(message)
	if err != nil {
		return fmt.Errorf("%s: Sending message error: %w", op, err)
	}

	return nil
}

func (dialer *Dialer) Send(message Message) error {
	var InvalidEmail = "invalid@mail"

	if message.To == InvalidEmail {
		return errors.New("invalid email")
	}

	log := dialer.log
	log.Debug("Message was sent", slog.String("To", message.To),
		slog.String("Subject", message.Subject), slog.String("Body", message.Body))

	return nil
}
