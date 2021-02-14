package util

import (
	"encoding/json"
	"os"
	"strconv"
	"time"

	"golang.org/x/xerrors"
)

func OutJson(v interface{}, testType string) error {
	// confirm if directory exists
	if _, err := os.Stat("result"); os.IsNotExist(err) {
		os.Mkdir("result", 0777)
	}

	outputJson, err := json.Marshal(&v)
	if err != nil {
		return xerrors.Errorf("Failed to change result into JSON: %w", err)
	}

	t := time.Now()
	filename := "result/" + strconv.Itoa(t.Year()) + strconv.Itoa(int(t.Month())) + strconv.Itoa(t.Day()) + strconv.Itoa(t.Hour()) + strconv.Itoa(t.Minute()) + strconv.Itoa(t.Second()) + "_" + testType + ".json"
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	defer f.Close()

	if err != nil {
		return xerrors.Errorf("Failed to create file pointer: %w", err)
	}

	f.Write(outputJson)
	return nil
}
