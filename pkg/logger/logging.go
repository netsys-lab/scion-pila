package logger

import (
	"fmt"
	"os"
	"time"
)

const (
	PARTS_LOG_LEVEL_DEBUG = 0
	PARTS_LOG_LEVEL_INFO  = 1
	PARTS_LOG_LEVEL_WARN  = 2
	PARTS_LOG_LEVEL_ERROR = 3
	PARTS_LOG_LEVEL_FATAL = 4
)

type Logger interface {
	Info(string, ...interface{})
	Error(string, ...interface{})
	Debug(string, ...interface{})
	Warn(string, ...interface{})
	Fatal(string, ...interface{})
	Infof(string, ...interface{})
	Errorf(string, ...interface{})
	Debugf(string, ...interface{})
	Warnf(string, ...interface{})
	Fatalf(string, ...interface{})
}

type PilaLogger struct {
	out   *os.File
	Level int
}

var Log *PilaLogger

func SetLogOutput(logger *os.File) {
	Log.out = logger
}

func SetLogLevel(level int) {
	Log.Level = level
}

func init() {
	Log = &PilaLogger{
		out:   os.Stdout,
		Level: PARTS_LOG_LEVEL_INFO,
	}
}

func (l *PilaLogger) Info(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_INFO {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " INFO: " + value)
	for _, arg := range args {
		l.out.WriteString(fmt.Sprintf("%v, ", arg))
	}

	l.out.WriteString("\n")
}

func (l *PilaLogger) Debug(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_DEBUG {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " DEBUG: " + value)
	for _, arg := range args {
		l.out.WriteString(fmt.Sprintf("%v", arg))
	}

	l.out.WriteString("\n")
}

func (l *PilaLogger) Error(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_ERROR {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " ERROR: " + value)
	for _, arg := range args {
		l.out.WriteString(fmt.Sprintf("%v", arg))
	}

	l.out.WriteString("\n")
}

func (l *PilaLogger) Warn(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_WARN {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " WARN: " + value)
	for _, arg := range args {
		l.out.WriteString(fmt.Sprintf("%v", arg))
	}

	l.out.WriteString("\n")
}

func (l *PilaLogger) Fatal(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_FATAL {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " FATAL: " + value)
	for _, arg := range args {
		l.out.WriteString(fmt.Sprintf("%v", arg))
	}

	l.out.WriteString("\n")
	os.Exit(1)
}

/*
 * ----------------------- Printf functions ------------------------------
 */
func (l *PilaLogger) Infof(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_INFO {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " INFO: " + fmt.Sprintf(value, args...))
	l.out.WriteString("\n")
}

func (l *PilaLogger) Debugf(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_DEBUG {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " DEBUG: " + fmt.Sprintf(value, args...))
	l.out.WriteString("\n")
}

func (l *PilaLogger) Errorf(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_ERROR {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " ERROR: " + fmt.Sprintf(value, args...))

	l.out.WriteString("\n")
}

func (l *PilaLogger) Warnf(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_WARN {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " WARN: " + fmt.Sprintf(value, args...))

	l.out.WriteString("\n")
}

func (l *PilaLogger) Fatalf(value string, args ...interface{}) {

	if l.Level > PARTS_LOG_LEVEL_FATAL {
		return
	}

	t := time.Now().Format("2006-01-02 15:04:05")
	l.out.WriteString(t + " FATAL: " + fmt.Sprintf(value, args...))

	l.out.WriteString("\n")
	os.Exit(1)
}
