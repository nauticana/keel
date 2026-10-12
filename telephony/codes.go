package telephony

type Kind string

const (
	KindCall    Kind = "C"
	KindMessage Kind = "M"
)

type Direction string

const (
	DirectionInbound  Direction = "I"
	DirectionOutbound Direction = "O"
)

type MessageStatus string

const (
	MessageReceived  MessageStatus = "R"
	MessageSent      MessageStatus = "S"
	MessageDelivered MessageStatus = "D"
	MessageFailed    MessageStatus = "F"
)
