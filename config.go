package certool

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

type Config struct {
	Dir    string `json:"-"`
	CAName string `json:"caName"`
	CAKey  string `json:"caKey"`
	CACrt  string `json:"caCrt"`
	Scheme string `json:"scheme"`
}

var DefaultConfig = Config{
	Dir:    fmt.Sprintf("%s/.config/certool", os.Getenv("HOME")),
	CAName: "ca.journey",
	CAKey:  fmt.Sprintf("%s/.config/certool/%s.key", os.Getenv("HOME"), "ca.journey"),
	CACrt:  fmt.Sprintf("%s/.config/certool/%s.crt", os.Getenv("HOME"), "ca.journey"),
	Scheme: "ed25519",
}

var config = DefaultConfig

func (c Config) Save() (err error) {
	var file []byte
	file, err = json.MarshalIndent(c, "", " ")
	if err != nil {
		err = fmt.Errorf("issue marshalling config file %w", err)
		return
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
		config.Save()
		return
	}

	c, err := ioutil.ReadFile(fmt.Sprintf("%s/config.json", config.Dir))
	if err != nil {
		err = fmt.Errorf("issue reading config %w", err)
		return
	}
	err = json.Unmarshal(c, &config)
	return
}
func LoadConfigFromFile(location string) (err error) {
	c, err := ioutil.ReadFile(fmt.Sprintf("%s/config.json", location))
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

func (c *Config) GetCAPassword() string {
	fmt.Printf("CA Password (hit enter if unencrypted)\n-> ")
	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("\n")
	return string(bytePassword)

}
