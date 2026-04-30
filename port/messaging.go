package port

import "context"

type MessagePublisher interface {
	Publish(ctx context.Context, topic string, data []byte, attributes map[string]string) error
	Close() error
}

type MessageSubscriber interface {
	Subscribe(ctx context.Context, subscription string, handler MessageHandler) error
	Close() error
}

type MessageHandler func(ctx context.Context, msg *Message) error

type Message struct {
	ID         string
	Data       []byte
	Attributes map[string]string
	Ack        func()
	Nack       func()
}
