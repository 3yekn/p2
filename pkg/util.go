package pkg

import (
	"encoding/json"
	"io/ioutil"

	"github.com/dfuse-io/cli"
)

func SaveToFile(fileName string, contents interface{}) error {

	contentsS, err := json.MarshalIndent(contents, "", "  ")
	cli.NoError(err, "cannot marshall customer to string")

	err = ioutil.WriteFile(fileName, contentsS, 0644)
	cli.NoError(err, "cannot write file")
	return nil
}
