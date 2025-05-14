package utils

import (
	"log"
	"os"
)

// Logger defines a simple interface for logging.
// This allows for easy replacement with a more sophisticated logger if needed.
type Logger interface {
	Debugf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Warnf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
	Fatalf(format string, v ...interface{})
}

// defaultLogger is a basic implementation of the Logger interface using the standard log package.
type defaultLogger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	fatalLogger *log.Logger
	logLevel    LogLevel // For controlling output verbosity
}

// LogLevel defines the verbosity of the logger.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// NewDefaultLogger creates a new logger with a specified log level.
func NewDefaultLogger(level LogLevel) Logger {
	return &defaultLogger{
		debugLogger: log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
		infoLogger:  log.New(os.Stdout, "INFO:  ", log.Ldate|log.Ltime|log.Lshortfile),
		warnLogger:  log.New(os.Stdout, "WARN:  ", log.Ldate|log.Ltime|log.Lshortfile),
		errorLogger: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
		fatalLogger: log.New(os.Stderr, "FATAL: ", log.Ldate|log.Ltime|log.Lshortfile),
		logLevel:    level,
	}
}

func (l *defaultLogger) Debugf(format string, v ...interface{}) {
	if l.logLevel <= LevelDebug {
		l.debugLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Infof(format string, v ...interface{}) {
	if l.logLevel <= LevelInfo {
		l.infoLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Warnf(format string, v ...interface{}) {
	if l.logLevel <= LevelWarn {
		l.warnLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Errorf(format string, v ...interface{}) {
	if l.logLevel <= LevelError {
		l.errorLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Fatalf(format string, v ...interface{}) {
	if l.logLevel <= LevelFatal {
		l.fatalLogger.Fatalf(format, v...)
	}
} 