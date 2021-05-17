package main

import (
	"testing"
)

func TestNewConfig(t *testing.T) {

	cfgPath := "./test_data/valid_config.yaml"
	_, err := NewConfig(cfgPath)
	if err != nil {
		t.Errorf("config at %s is valid and supposed to be parsed, instead ended up with %s", cfgPath, err.Error())
	}

	cfgPath = "./test_data/invalid_config_time.yaml"
	_, err = NewConfig(cfgPath)
	if err == nil {
		t.Errorf("config at %s has invalid time, and parsing it should cause an error", cfgPath)
	}

	cfgPath = "./test_data/invalid_config_action.yaml"
	_, err = NewConfig(cfgPath)
	if err == nil {
		t.Errorf("config at %s has invalid action, and parsing it should cause an error", cfgPath)
	}

}
