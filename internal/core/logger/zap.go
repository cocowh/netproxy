package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// zapLogger implements the Logger interface using uber-go/zap
type zapLogger struct {
	logger *zap.Logger
	atom   zap.AtomicLevel
	mu     sync.RWMutex
}

// NewZapLogger creates a new logger backed by zap
// opts can include file path for logging, etc.
func NewZapLogger(level Level, filePath string) (Logger, error) {
	atom := zap.NewAtomicLevel()
	atom.SetLevel(toZapLevel(level))

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var cores []zapcore.Core

	// Console output
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)
	cores = append(cores, zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), atom))

	// File output (if path provided)
	if filePath != "" {
		fileWriter := zapcore.AddSync(&lumberjack.Logger{
			Filename:   filePath,
			MaxSize:    100, // megabytes
			MaxBackups: 3,
			MaxAge:     28, // days
		})
		fileEncoder := zapcore.NewJSONEncoder(encoderConfig)
		cores = append(cores, zapcore.NewCore(fileEncoder, fileWriter, atom))
	}

	core := zapcore.NewTee(cores...)
	z := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &zapLogger{
		logger: z,
		atom:   atom,
	}, nil
}

func (l *zapLogger) Debug(msg string, fields ...Field) {
	l.logger.Debug(msg, toZapFields(fields)...)
}

func (l *zapLogger) Info(msg string, fields ...Field) {
	l.logger.Info(msg, toZapFields(fields)...)
}

func (l *zapLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn(msg, toZapFields(fields)...)
}

func (l *zapLogger) Error(msg string, fields ...Field) {
	l.logger.Error(msg, toZapFields(fields)...)
}

func (l *zapLogger) Fatal(msg string, fields ...Field) {
	l.logger.Fatal(msg, toZapFields(fields)...)
}

func (l *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{
		logger: l.logger.With(toZapFields(fields)...),
		atom:   l.atom,
	}
}

func (l *zapLogger) SetLevel(level Level) {
	l.atom.SetLevel(toZapLevel(level))
}

func (l *zapLogger) Sync() error {
	return l.logger.Sync()
}

func toZapFields(fields []Field) []zap.Field {
	zf := make([]zap.Field, len(fields))
	for i, f := range fields {
		zf[i] = zap.Any(f.Key, f.Value)
	}
	return zf
}

func toZapLevel(l Level) zapcore.Level {
	switch l {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case FatalLevel:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}
