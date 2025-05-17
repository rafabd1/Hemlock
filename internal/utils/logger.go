package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
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

// defaultLogger is a basic implementation of the Logger interface.
type defaultLogger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	fatalLogger *log.Logger
	logLevel    LogLevel
	noColor     bool
	silent      bool
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

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorDim    = "\033[2m"
	// colorPurple = "\033[35m"
	// colorCyan   = "\033[36m"
	// colorWhite  = "\033[37m"
)

func colorize(s string, color string, noColor bool) string {
	if noColor {
		return s
	}
	return color + s + colorReset
}

// NewDefaultLogger creates a new logger with specified options.
func NewDefaultLogger(level LogLevel, noColor bool, silent bool) Logger {
	flags := 0

	emptyPrefix := ""

	var debugOut io.Writer = os.Stdout
	var infoOut io.Writer = os.Stdout
	var warnOut io.Writer = os.Stdout
	var errorOut io.Writer = os.Stderr
	var fatalOut io.Writer = os.Stderr

	if silent {
		debugOut = io.Discard
		infoOut = io.Discard
		warnOut = io.Discard
	}

	return &defaultLogger{
		debugLogger: log.New(debugOut, emptyPrefix, flags),
		infoLogger:  log.New(infoOut, emptyPrefix, flags),
		warnLogger:  log.New(warnOut, emptyPrefix, flags),
		errorLogger: log.New(errorOut, emptyPrefix, flags),
		fatalLogger: log.New(fatalOut, emptyPrefix, flags),
		logLevel:    level,
		noColor:     noColor,
		silent:      silent,
	}
}

func (l *defaultLogger) logInternal(logger *log.Logger, levelStr string, levelColor string, format string, v ...interface{}) {
	currentTime := time.Now().Format("15:04:05")
	prefix := fmt.Sprintf("%s [%s] ",
		colorize(fmt.Sprintf("[%s]", currentTime), colorDim, l.noColor),
		colorize(levelStr, levelColor, l.noColor),
	)
	message := fmt.Sprintf(format, v...)
	logger.Print(prefix + message)
}

func (l *defaultLogger) logFatalfInternal(logger *log.Logger, levelStr string, levelColor string, format string, v ...interface{}) {
	currentTime := time.Now().Format("15:04:05")
	prefix := fmt.Sprintf("%s [%s] ",
		colorize(fmt.Sprintf("[%s]", currentTime), colorDim, l.noColor),
		colorize(levelStr, levelColor, l.noColor),
	)
	message := fmt.Sprintf(format, v...)
	logger.Fatal(prefix + message)
}

func (l *defaultLogger) Debugf(format string, v ...interface{}) {
	if l.silent && l.logLevel > LevelDebug {
		return
	}
	if l.logLevel <= LevelDebug {
		l.logInternal(l.debugLogger, "DEBUG", colorBlue, format, v...)
	}
}

func (l *defaultLogger) Infof(format string, v ...interface{}) {
	if l.silent && l.logLevel > LevelInfo {
		return
	}
	if l.logLevel <= LevelInfo {
		l.logInternal(l.infoLogger, "INFO", colorGreen, format, v...)
	}
}

func (l *defaultLogger) Warnf(format string, v ...interface{}) {
	if l.silent && l.logLevel > LevelWarn {
		return
	}
	if l.logLevel <= LevelWarn {
		l.logInternal(l.warnLogger, "WARN", colorYellow, format, v...)
	}
}

func (l *defaultLogger) Errorf(format string, v ...interface{}) {
	if l.logLevel <= LevelError {
		l.logInternal(l.errorLogger, "ERROR", colorRed, format, v...)
	}
}

func (l *defaultLogger) Fatalf(format string, v ...interface{}) {
	if l.logLevel <= LevelFatal {
		l.logFatalfInternal(l.fatalLogger, "FATAL", colorRed, format, v...)
	}
}

// StringToLogLevel converts a log level string to LogLevel type.
// Defaults to LevelInfo if the string is unrecognized.
func StringToLogLevel(levelStr string) LogLevel {
	switch strings.ToLower(levelStr) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal":
		return LevelFatal
	default:
		fmt.Fprintf(os.Stderr, "Unknown log level string '%s', defaulting to INFO.\n", levelStr)
		return LevelInfo
	}
} 