package logger

type ApplicationLogger interface {
	Initialize(root string, destination string) error
	Close()
	Access(log string)
	Info(log string)
	Warning(log string)
	Error(log string)
	Fatal(log string)
}
