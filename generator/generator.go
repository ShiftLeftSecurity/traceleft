package generator

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/golang/protobuf/jsonpb"
)

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

func unmarshalConfig(path string) (*Config, error) {
	p := &Config{}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := jsonpb.Unmarshal(file, p); err != nil {
		return nil, err
	}

	return p, nil
}

func buildSource(event *Event, tpl string, destDir string) error {
	ev := Event{
		event.Name,
		event.Args,
	}

	tplText, err := ioutil.ReadFile(tpl)
	if err != nil {
		return fmt.Errorf("could not read template: %v", err)
	}

	t := template.New("BPF Source")

	t, err = t.Parse(string(tplText))
	if err != nil {
		return fmt.Errorf("could not parse template: %v", err)
	}

	evPath := fmt.Sprintf("handle_syscall_%s.c", event.Name)

	fi, err := os.Create(filepath.Join(destDir, evPath))
	if err != nil {
		return fmt.Errorf("could not create BPF source: %v", err)
	}
	defer fi.Close()

	if err = t.Execute(fi, ev); err != nil {
		return fmt.Errorf("could not execute template: %v", err)
	}

	return nil
}

func GenerateBpfSources(configPath string, tpl string, destDir string) error {
	if !fileExists(tpl) {
		return fmt.Errorf("template file doesn't exist")
	}

	if f, err := os.Stat(destDir); err != nil || !f.IsDir() {
		return fmt.Errorf("invalid destination directory: %v", err)
	}

	if !fileExists(configPath) {
		return fmt.Errorf("config file %q doesn't exist", configPath)
	}

	// Uses the PB config struct directly
	config, err := unmarshalConfig(configPath)
	if err != nil {
		return fmt.Errorf("could not read config: %v", err)
	}

	for _, event := range config.Event {
		if err := buildSource(event, tpl, destDir); err != nil {
			return fmt.Errorf("could not build source: %v", err)
		}
	}
	return nil
}
