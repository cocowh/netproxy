package logger

// Level defines the log level
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// Field represents a structured log field
type Field struct {
	Key   string
	Value interface{}
}

// Logger interface defines the behavior of the logging system
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)

	// With creates a child logger with the provided fields
	With(fields ...Field) Logger

	// SetLevel dynamically changes the log level
	SetLevel(level Level)

	// Sync flushes any buffered log entries
	Sync() error
}

// Any creates a new Field
func Any(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}
