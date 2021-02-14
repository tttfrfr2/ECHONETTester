package util

import (
	"encoding/pem"
	"os"
	"strings"

	"golang.org/x/xerrors"
)

func WriteByteFile(path string, data []byte, isAppend bool) (err error) {
	var file *os.File
	Check_dir(path)
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

func WritePEMFile(path string, block *pem.Block, perm os.FileMode) (err error) {
	var file *os.File
	Check_dir(path)
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

func Check_dir(path string) {
	dirs := strings.Split(path, "/")
	path = ""
	for i := 0; i < len(dirs)-1; i++ {
		path = path + dirs[i] + "/"
		if _, err := os.Stat(path); os.IsNotExist(err) {
			os.Mkdir(path, 0777)
		}
	}
}
