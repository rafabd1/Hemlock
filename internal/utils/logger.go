package utils

import (
	"fmt"
	"io" // Adicionado para io.Writer
	"io/ioutil"
	"log"
	"os"
	"strings"
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
	LevelDebug LogLevel = iota // Exported: utils.LevelDebug
	LevelInfo                  // Exported: utils.LevelInfo
	LevelWarn                  // Exported: utils.LevelWarn
	LevelError                 // Exported: utils.LevelError
	LevelFatal                 // Exported: utils.LevelFatal
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
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
	flags := log.Ldate | log.Ltime | log.Lshortfile

	debugPrefix := "DEBUG: "
	infoPrefix := "INFO:  "
	warnPrefix := "WARN:  "
	errorPrefix := "ERROR: "
	fatalPrefix := "FATAL: "

	if !noColor {
		debugPrefix = colorize(debugPrefix, colorBlue, noColor)
		infoPrefix = colorize(infoPrefix, colorGreen, noColor)
		warnPrefix = colorize(warnPrefix, colorYellow, noColor)
		errorPrefix = colorize(errorPrefix, colorRed, noColor)
		fatalPrefix = colorize(fatalPrefix, colorRed, noColor)
	}

	// Se silent, a maioria dos logs vai para ioutil.Discard
	var debugOut io.Writer = os.Stdout
	var infoOut io.Writer = os.Stdout
	var warnOut io.Writer = os.Stdout
	// errorOut e fatalOut sempre serão os.Stderr
	var errorOut io.Writer = os.Stderr
	var fatalOut io.Writer = os.Stderr

	if silent {
		debugOut = ioutil.Discard
		infoOut = ioutil.Discard
		warnOut = ioutil.Discard
		// error e fatal continuam em stderr
	}

	return &defaultLogger{
		debugLogger: log.New(debugOut, debugPrefix, flags),
		infoLogger:  log.New(infoOut, infoPrefix, flags),
		warnLogger:  log.New(warnOut, warnPrefix, flags),
		errorLogger: log.New(errorOut, errorPrefix, flags),
		fatalLogger: log.New(fatalOut, fatalPrefix, flags),
		logLevel:    level,
		noColor:     noColor,
		silent:      silent,
	}
}

func (l *defaultLogger) Debugf(format string, v ...interface{}) {
	if l.silent && l.logLevel > LevelDebug { // Em silent, debug só loga se o nível for explicitamente debug
		return
	}
	if l.logLevel <= LevelDebug {
		l.debugLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Infof(format string, v ...interface{}) {
	if l.silent && l.logLevel > LevelInfo { // Em silent, info só loga se o nível for info/debug
		return
	}
	if l.logLevel <= LevelInfo {
		l.infoLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Warnf(format string, v ...interface{}) {
	if l.silent && l.logLevel > LevelWarn { // Em silent, warn só loga se o nível for warn/info/debug
		return
	}
	if l.logLevel <= LevelWarn {
		l.warnLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Errorf(format string, v ...interface{}) {
	// Errorf sempre loga, independente de silent, se o nível de log permitir
	if l.logLevel <= LevelError {
		l.errorLogger.Printf(format, v...)
	}
}

func (l *defaultLogger) Fatalf(format string, v ...interface{}) {
	// Fatalf sempre loga, independente de silent, se o nível de log permitir (que sempre será, por ser fatal)
	if l.logLevel <= LevelFatal {
		l.fatalLogger.Fatalf(format, v...)
	}
	// Fallback se por algum motivo o nível de log for maior que fatal (não deveria acontecer)
	// ou se o logger não chamar os.Exit(1) por si só.
	// No entanto, log.Fatalf já chama os.Exit(1).
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
		// Usar fmt para evitar dependência cíclica se o logger padrão ainda não estiver inicializado
		// ou se este for chamado antes do logger global ser setado.
		fmt.Fprintf(os.Stderr, "Unknown log level string '%s', defaulting to INFO.\n", levelStr)
		return LevelInfo
	}
} 