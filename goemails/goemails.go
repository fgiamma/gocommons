package goemails

import (
	"net/smtp"
	"strings"
)

func SendEmailWithPort(smtpServer string, smtpPort string, smtpUser string, smtpPassword string, from string, to []string, subject string, message string) error {
	addr := smtpServer + ":" + smtpPort

	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := "<html><body>" + message + "</body></html>"

	msg := []byte("To: " + strings.Join(to[:], ",") + "\r\n" + "Subject:" + subject + "\r\n" + mime + body)

	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpServer)
	err := smtp.SendMail(addr, auth, from, to, msg)

	if err != nil {
		return err
	}

	return nil
}

func SendEmail(smtpServer string, smtpUser string, smtpPassword string, from string, to []string, subject string, message string) error {
	return SendEmailWithPort(smtpServer, "587", smtpUser, smtpPassword, from, to, subject, message)
}
