package generator

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

const CONFIGPB_FILE string = "config.data"

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

// Converts PB to JSON and writes on disk for re-reading later on
func writePBFromJSON(pathToJson string) error {
	p := &Config{}
	file, err := os.Open(pathToJson)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := jsonpb.Unmarshal(file, p); err != nil {
		return err
	}

	out, err := proto.Marshal(p)
	if err != nil {
		return err
	}

	configPbPath := filepath.Join(filepath.Dir(pathToJson), CONFIGPB_FILE)
	if err := ioutil.WriteFile(configPbPath, out, 0644); err != nil {
		return err
	}

	return nil
}

func getConfigFromPB(pathToPB string) (*Config, error) {
	p := &Config{}
	in, err := ioutil.ReadFile(pathToPB)
	if err != nil {
		return nil, err
	}

	if err := proto.Unmarshal(in, p); err != nil {
		return nil, err
	}
	return p, nil
}

func unmarshalConfig(path string) (*Config, error) {
	// TODO: Only for now - till we have a way to get PB on the wire
	if err := writePBFromJSON(path); err != nil {
		return nil, err
	}

	configPbPath := filepath.Join(filepath.Dir(path), CONFIGPB_FILE)
	config, err := getConfigFromPB(configPbPath)
	if err != nil {
		return nil, err
	}

	return config, nil
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
