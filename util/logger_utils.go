package util

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitLogger(filePath string) *zap.Logger {
	logFilePath := filepath.Dir("log/" + filePath)
	consoleConfig := zapcore.EncoderConfig{
		TimeKey:        "Time",
		LevelKey:       "Level",
		NameKey:        "Name",
		CallerKey:      "Caller",
		MessageKey:     "Msg",
		StacktraceKey:  "St",
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	jsonConfig := zapcore.EncoderConfig{
		TimeKey:        "Time",
		LevelKey:       "Level",
		NameKey:        "Name",
		CallerKey:      "Caller",
		MessageKey:     "Msg",
		StacktraceKey:  "St",
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	err := Check_dir(logFilePath)
	if err != nil {
		fmt.Printf("Directory check exist error: %s\n", err)
		return nil
	}
	file, err := os.Create(logFilePath)
	if err != nil {
		fmt.Printf("Create file error: %s", err)
	}
	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(consoleConfig),
		zapcore.AddSync(os.Stdout),
		zapcore.DebugLevel,
	)

	logCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(jsonConfig),
		zapcore.AddSync(file),
		zapcore.InfoLevel,
	)

	logger := zap.New(zapcore.NewTee(
		consoleCore,
		logCore,
	))

	return logger
}
