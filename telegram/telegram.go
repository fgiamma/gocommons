package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
)

func NewTelegram(token string, chatId string) Telegram {
	t := Telegram{}
	t.SetUrl(token, chatId)
	return t
}

type TelegramMessage struct {
	ChatID int64  `json:"chat_id"`
	Text   string `json:"text"`
}

type Telegram struct {
	Url    string `json:"url"`
	ChatId int64  `json:"chat_id"`
}

func (t *Telegram) SetUrl(token string, chatId string) error {
	t.Url = fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	chatIdNumber, err := strconv.ParseInt(chatId, 10, 64)
	if err != nil {
		return err
	}

	t.ChatId = chatIdNumber
	return nil
}

// SendMessage sends a message to given URL.
func (t *Telegram) SendMessage(messageString string) error {
	message := TelegramMessage{
		ChatID: t.ChatId,
		Text:   messageString,
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	response, err := http.Post(t.Url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			log.Println("failed to close response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send successful request. Status was %q", response.Status)
	}
	return nil
}
