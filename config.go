package certs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/taybart/certs/scheme"
	"github.com/taybart/log"
)

type CAConfig struct {
	Name   string `json:"name,omitempty" label:"CA name"`
	Key    string `json:"key,omitempty" label:"CA key file name"`
	Crt    string `json:"crt,omitempty" label:"CA certificate file name"`
	Scheme string `json:"scheme,omitempty" label:"Cryptographic scheme"`
}
type Config struct {
	Dir            string         `json:"-"`
	CA             CAConfig       `json:"ca" label:""`
	DefaultSubject scheme.Subject `json:"default_subject"`
}

var DefaultConfig = Config{
	Dir: fmt.Sprintf("%s/.config/certs", os.Getenv("HOME")),
	CA: CAConfig{
		Name:   "My CA",
		Key:    fmt.Sprintf("%s/.config/certs/profiles/default/ca.key", os.Getenv("HOME")),
		Crt:    fmt.Sprintf("%s/.config/certs/profiles/default/ca.crt", os.Getenv("HOME")),
		Scheme: "ecdsa256",
	},
	DefaultSubject: scheme.Subject{
		CommonName:         "taybart",
		OrganizationalUnit: []string{"Engineering"},
		Organization:       []string{"taybart"},
		StreetAddress:      []string{""},
		PostalCode:         []string{""},
		Locality:           []string{""},
		Province:           []string{""},
		Country:            []string{""},
	},
}

var config = DefaultConfig

func (c *Config) FirstRun() (err error) {
	env := make(map[string]string)
	for _, v := range os.Environ() {
		split := strings.Split(v, "=")
		env[split[0]] = split[1]
	}

	fmt.Printf("%sError:%s Could not load config, let's set up.\n", log.Red, log.Rtd)
	fmt.Printf("%sNote:%s You can use ENV vars like this -> {{ .HOME }} => %s\n", log.Yellow, log.Rtd, env["HOME"])
	fmt.Printf("      Hit enter to use default values, labeled with (%svalue%s)\n\n", log.Blue, log.Rtd)
	rt := reflect.TypeOf(c.CA)
	if rt.Kind() != reflect.Struct {
		err = fmt.Errorf("issue getting config fields")
		return
	}
	fmt.Println("Certificate authority details...")
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		defaultValue := reflect.ValueOf(DefaultConfig.CA).Field(i).String()

		var res string
		res, err = readConfigVar(formatVarPrompt(f.Tag.Get("label"), defaultValue))
		if err != nil {
			return
		}
		if res == "" {
			reflect.ValueOf(&c.CA).Elem().Field(i).SetString(defaultValue)
			continue
		}
		var buf bytes.Buffer
		t := template.Must(template.New("conf").Parse(res))
		err = t.Execute(&buf, env)
		if err != nil {
			return
		}

		reflect.ValueOf(&c.CA).Elem().Field(i).SetString(buf.String())
	}

	rt = reflect.TypeOf(c.DefaultSubject)
	if rt.Kind() != reflect.Struct {
		err = fmt.Errorf("issue getting config fields")
		return
	}
	fmt.Println("Default CSR Subject...")
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Tag.Get("label") == "" {
			continue
		}
		var res string
		switch f.Type.Kind() {
		case reflect.String:
			d := reflect.ValueOf(DefaultConfig.DefaultSubject).Field(i).String()

			res, err = readConfigVar(formatVarPrompt(f.Tag.Get("label"), d))
			if err != nil {
				return
			}
			if res == "" {
				reflect.ValueOf(&c.DefaultSubject).Elem().Field(i).SetString(d)
				continue
			}
			var buf bytes.Buffer
			t := template.Must(template.New("conf").Parse(res))
			err = t.Execute(&buf, env)
			if err != nil {
				return
			}
			reflect.ValueOf(&c.CA).Elem().Field(i).SetString(buf.String())

		case reflect.Slice:
			sf := reflect.ValueOf(DefaultConfig.DefaultSubject).Field(i)
			res, err = readConfigVar(formatVarPrompt(f.Tag.Get("label"), sf))
			if err != nil {
				return
			}
			if res == "" {
				reflect.ValueOf(&c.DefaultSubject).Elem().Field(i).Set(sf)
				continue
			}
			var buf bytes.Buffer
			t := template.Must(template.New("conf").Parse(res))
			err = t.Execute(&buf, env)
			if err != nil {
				return
			}

			arr := strings.Split(buf.String(), ",")
			reflect.ValueOf(&c.DefaultSubject).Elem().Field(i).Set(reflect.ValueOf(arr))
		default:
			err = errors.New("Unkown field in config")
			return
		}
	}
	return
}

func (c Config) Save() (err error) {
	var file []byte
	file, err = json.MarshalIndent(c, "", " ")
	if err != nil {
		err = fmt.Errorf("issue marshalling config file %w", err)
		return
	}

	if _, err = os.Stat(config.Dir); os.IsNotExist(err) {
		err = os.MkdirAll(config.Dir, 0755)
		if err != nil {
			err = fmt.Errorf("issue creating config folder %w", err)
			return
		}
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/config.json", c.Dir), file, 0600)
	if err != nil {
		err = fmt.Errorf("issue writing config file %w", err)
		return
	}
	return
}

func LoadConfig(configLocation string) (err error) {
	config.Dir = configLocation
	if _, err = os.Stat(config.Dir); os.IsNotExist(err) {
		err = os.MkdirAll(config.Dir, 0755)
		if err != nil {
			err = fmt.Errorf("issue creating config folder %w", err)
			return
		}
	}
	if _, err = os.Stat(fmt.Sprintf("%s/config.json", config.Dir)); os.IsNotExist(err) {
		err = nil
		err = config.FirstRun()
		if err != nil {
			panic(fmt.Errorf("Could not set up config %w", err))
		}
		err = config.Save()
		if err != nil {
			panic(fmt.Errorf("Could not save new config %w", err))
		}
	} else if err != nil {
		return err
	}

	c, err := ioutil.ReadFile(fmt.Sprintf("%s/config.json", config.Dir))
	if err != nil {
		err = fmt.Errorf("issue reading config %w", err)
		return
	}
	err = json.Unmarshal(c, &config)
	if err != nil {
		err = fmt.Errorf("issue reading config %w", err)
		return
	}
	// Set default Subject
	scheme.SetDefaultSubject(config.DefaultSubject)

	return
}

func LoadConfigFromFile(location string) (err error) {
	c, err := ioutil.ReadFile(location)
	if err != nil {
		err = fmt.Errorf("issue reading config %w", err)
		return
	}
	err = json.Unmarshal(c, &config)
	if err != nil {
		err = fmt.Errorf("issue marshalling config %w", err)
		return
	}
	return
}

func GetDefaultSubject() scheme.Subject {
	return config.DefaultSubject
}
func GetDefaultScheme() string {
	return config.CA.Scheme
}

func (c *Config) GetCAPassword() []byte {
	fmt.Printf("Enter CA Password -> ")
	tty, err := os.Open("/dev/tty") // Use tty just in case stdin is pipe
	if err != nil {
		panic(fmt.Errorf("can't open /dev/tty: %w", err))
	}
	bytePassword, err := terminal.ReadPassword(int(tty.Fd()))
	if err != nil {
		panic(err)
	}

	return bytePassword

}

func formatVarPrompt(label string, defaultValue interface{}) string {
	return fmt.Sprintf("%s%s%s (%s%s%s) -> ",
		log.BoldGreen, label, log.Rtd,
		log.Blue, defaultValue, log.Rtd)
}

func readConfigVar(prompt string) (val string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s", prompt)
	val, err = reader.ReadString('\n')
	if err != nil {
		return
	}
	val = strings.TrimSuffix(val, "\n")
	return
}
