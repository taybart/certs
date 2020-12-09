package certs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

type CAConfig struct {
	Name   string `json:"name,omitempty" label:"CA name"`
	Key    string `json:"key,omitempty" label:"CA key file name"`
	Crt    string `json:"crt,omitempty" label:"CA certificate file name"`
	Scheme string `json:"scheme,omitempty" label:"Cryptographic scheme"`
}
type Config struct {
	Dir string   `json:"-"`
	CA  CAConfig `json:"ca" label:""`
}

var DefaultConfig = Config{
	Dir: fmt.Sprintf("%s/.config/certs", os.Getenv("HOME")),
	CA: CAConfig{
		Name:   "My CA",
		Key:    fmt.Sprintf("%s/.config/certs/%s.key", os.Getenv("HOME"), "ca.certs"),
		Crt:    fmt.Sprintf("%s/.config/certs/%s.crt", os.Getenv("HOME"), "ca.certs"),
		Scheme: "ed25519",
	},
}

var config = DefaultConfig

func (c *Config) FirstRun() (err error) {
	env := make(map[string]string)
	for _, v := range os.Environ() {
		split := strings.Split(v, "=")
		env[split[0]] = split[1]
	}

	fmt.Printf("\033[32mCould not load config, let's set up.\n\n")
	fmt.Printf("\033[33mNote: ENV vars look like this -> {{ .HOME }} => %s\033[0m\n\n", env["HOME"])
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
		res, err = readConfigVar(fmt.Sprintf("Enter %s (default: %s) -> ", f.Tag.Get("label"), defaultValue))
		if err != nil {
			return
		}
		if res == "" {
			reflect.ValueOf(&c.CA).Elem().Field(i).SetString(defaultValue)
			continue
		}
		var buf bytes.Buffer
		t := template.Must(template.New("conf").Parse(res))
		t.Execute(&buf, env)
		reflect.ValueOf(&c.CA).Elem().Field(i).SetString(buf.String())
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
		config.FirstRun()
		config.Save()
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

func readConfigVar(prompt string) (val string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf(prompt)
	val, err = reader.ReadString('\n')
	if err != nil {
		return
	}
	val = strings.TrimSuffix(val, "\n")
	return
}
