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
}

var DefaultConfig = Config{
	Dir:    fmt.Sprintf("%s/.config/certool", os.Getenv("HOME")),
	CAName: "ca.journey",
	CAKey:  fmt.Sprintf("%s/.config/certool/%s.key", os.Getenv("HOME"), "ca.journey"),
	CACrt:  fmt.Sprintf("%s/.config/certool/%s.crt", os.Getenv("HOME"), "ca.journey"),
}

var config = DefaultConfig

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
		var file []byte
		file, err = json.MarshalIndent(config, "", " ")
		if err != nil {
			err = fmt.Errorf("issue marshalling config file %w", err)
			return
		}

		err = ioutil.WriteFile(fmt.Sprintf("%s/config.json", config.Dir), file, 0600)
		if err != nil {
			err = fmt.Errorf("issue writing config file %w", err)
			return
		}
		fmt.Println("[WARNING] default password used")
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
	fmt.Printf("CA Password: ")
	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("\n")
	return string(bytePassword)

}
