package generator

import (
	"text/template"
	"os"
	"fmt"
	"io/ioutil"
	"github.com/prometheus/common/log"
	"path/filepath"
)

type Event struct {
	EventName string
}

func fileExists(path string) bool {
	if f, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
		if f.IsDir() {
			return false
		}
	}
	return true
}

func GenerateBpfSources(events []string, tpl string, destDir string) {
	if !fileExists(tpl) {
		log.Fatalf("Template file doesn't exist")
	}

	if f, err := os.Stat(destDir); err != nil || !f.IsDir() {
		log.Fatalf("Invalid destination directory")
	}

	for _, eventString := range events {
		ev := Event{eventString}

		tplText, err := ioutil.ReadFile(tpl)
		if err != nil {
			fmt.Print(err)
		}

		t := template.New("BPF Source")

		t, err = t.Parse(string(tplText))
		if err != nil {
			fmt.Errorf(err.Error())
		}

		evPath := fmt.Sprintf("handle_%s.c", eventString)

		fi, err := os.Create(filepath.Join(destDir, evPath))
		if err != nil {
			log.Fatalf(err.Error())
			return
		}

		err = t.Execute(fi, ev)
		if err != nil {
			fmt.Errorf(err.Error())
		}

		fi.Close()
	}
}
