package util

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

func WriteByteFile(path string, data []byte, isAppend bool) (err error) {
	var file *os.File
	err = Check_dir(path)
	if err != nil {
		return xerrors.Errorf("Directory check exist error: %w", err)
	}
	if isAppend {
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return xerrors.Errorf("Failed to open file: %v, path: %s", err, path)
		}
	} else {
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			return xerrors.Errorf("Failed to open file: %v, path: %s", err, path)
		}
	}
	defer file.Close()
	length := len(data)
	n, err := file.Write(data)
	if err != nil || n != length {
		return xerrors.Errorf("Failed to write data: %v, Wrote byte size: %d", err, n)
	}
	return nil
}

func WritePEMFile(path string, block *pem.Block, perm os.FileMode) error {
	var file *os.File
	err := Check_dir(path)
	if err != nil {
		return xerrors.Errorf("Directory check exist error: %w", err)
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return xerrors.Errorf("Failed to open file: %v, path: %s", err, path)
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return xerrors.Errorf("Failed to encode pem type: %v", err)
	}
	return nil
}

func Check_dir(path string) error {
	dirs := strings.Split(path, "/")
	path = ""
	for i := 0; i < len(dirs)-1; i++ {
		path = path + dirs[i] + "/"
		dirPath, filePath := filepath.Split(path)
		if _, err := os.Stat(dirPath + filePath); os.IsNotExist(err) {
			err := os.Mkdir(dirPath+filePath, 0777)
			if err != nil {
				return xerrors.Errorf("Create directory failed: %w", err)
			}
		}
	}
	return nil
}
