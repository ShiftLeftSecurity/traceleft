package generator

import (
	"text/template"
	"os"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"log"
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

	err = jsonpb.Unmarshal(file, p)
	if err != nil {
		return err
	}

	out, err := proto.Marshal(p)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(CONFIGPB_FILE, out, 0644)
	if err != nil {
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

	err = proto.Unmarshal(in, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func unmarshalConfig(path string) (*Config, error) {
	// TODO: Only for now - till we have a way to get PB on the wire
	err := writePBFromJSON(path)
	if err != nil {
		return nil, err
	}

	config, err := getConfigFromPB(CONFIGPB_FILE)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func GenerateBpfSources(configPath string, tpl string, destDir string) {
	if !fileExists(tpl) {
		log.Fatalf("Template file doesn't exist")
	}

	if f, err := os.Stat(destDir); err != nil || !f.IsDir() {
		log.Fatalf("Invalid destination directory")
	}

	if !fileExists(configPath) {
		log.Fatalf("Config file doesn't exist")
	}

	// Uses the PB config struct directly
	config, err := unmarshalConfig(configPath)
	if err != nil {
		log.Fatalf("Could not read config")
	}

	for _, event := range config.Event {
		ev := Event{
			Name:event.Name,
		}

		tplText, err := ioutil.ReadFile(tpl)
		if err != nil {
			fmt.Print(err)
		}

		t := template.New("BPF Source")

		t, err = t.Parse(string(tplText))
		if err != nil {
			fmt.Errorf(err.Error())
		}

		evPath := fmt.Sprintf("handle_%s.c", event.Name)

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
