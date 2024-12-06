package gomail

import (
	"crypto/tls"
	"fmt"

	"gopkg.in/mail.v2"

	"auth/internal/config"
)

type Email struct {
	Dialer *mail.Dialer
}

func New(config config.Email) *Email {
	d := mail.NewDialer(config.Host, config.Port, config.From, config.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	return &Email{Dialer: d}
}

func (e *Email) SendIpWarnig(to, ip string) error {
	const op = "email.gomail.SendIpWarnig"

	message := mail.NewMessage()
	message.SetHeader("From", e.Dialer.Username)
	message.SetHeader("To", to)
	message.SetHeader("Subject", "New IP warning")
	message.SetBody("text/plain", "IP: "+ip)

	err := e.Dialer.DialAndSend(message)
	if err != nil {
		return fmt.Errorf("%s: Sending email error: %w", op, err)
	}

	return nil
}
