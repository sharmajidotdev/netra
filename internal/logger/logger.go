package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level represents the logging level
type Level int

const (
	// LevelDebug logs everything
	LevelDebug Level = iota
	// LevelInfo logs info and above
	LevelInfo
	// LevelWarn logs warnings and above
	LevelWarn
	// LevelError logs only errors
	LevelError
)

var (
	levelNames = map[Level]string{
		LevelDebug: "DEBUG",
		LevelInfo:  "INFO",
		LevelWarn:  "WARN",
		LevelError: "ERROR",
	}

	levelColors = map[Level]string{
		LevelDebug: "\033[36m", // Cyan
		LevelInfo:  "\033[32m", // Green
		LevelWarn:  "\033[33m", // Yellow
		LevelError: "\033[31m", // Red
	}

	reset = "\033[0m"
)

// ParseLevel converts a string level to Level
func ParseLevel(level string) Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// Logger represents a logger instance
type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	level  Level
	color  bool
	prefix string
}

var defaultLogger = New(os.Stderr, LevelInfo)

// New creates a new logger
func New(out io.Writer, level Level) *Logger {
	return &Logger{
		out:   out,
		level: level,
		color: true,
	}
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput sets the output writer
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

// SetColor enables/disables color output
func (l *Logger) SetColor(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.color = enabled
}

// SetPrefix sets a prefix for all log messages
func (l *Logger) SetPrefix(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefix = prefix
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().Format("2006-01-02 15:04:05")
	levelName := levelNames[level]
	msg := fmt.Sprintf(format, args...)

	if l.color {
		colorCode := levelColors[level]
		fmt.Fprintf(l.out, "%s [%s%s%s] %s%s%s\n",
			now, colorCode, levelName, reset,
			l.prefix, msg, reset)
	} else {
		fmt.Fprintf(l.out, "%s [%s] %s%s\n",
			now, levelName, l.prefix, msg)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

// Global logger functions
func SetLevel(level Level)                     { defaultLogger.SetLevel(level) }
func SetOutput(w io.Writer)                    { defaultLogger.SetOutput(w) }
func SetColor(enabled bool)                    { defaultLogger.SetColor(enabled) }
func SetPrefix(prefix string)                  { defaultLogger.SetPrefix(prefix) }
func Debug(format string, args ...interface{}) { defaultLogger.Debug(format, args...) }
func Info(format string, args ...interface{})  { defaultLogger.Info(format, args...) }
func Warn(format string, args ...interface{})  { defaultLogger.Warn(format, args...) }
func Error(format string, args ...interface{}) { defaultLogger.Error(format, args...) }
