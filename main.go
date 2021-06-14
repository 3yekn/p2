package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/dappdever/p2/encryption"
	"github.com/dappdever/p2/pkg"
	cli "github.com/dfuse-io/cli"
	"github.com/dfuse-io/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var zlog = zap.NewNop()

//lint:ignore U1000 leveraged at runtime
var tracer = logging.ApplicationLogger("p2", "github.com/dappdever/p2", &zlog)

func main() {

	zlog.Debug("cli args", zap.Strings("args", os.Args))

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.SetEnvPrefix("P2")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		zlog.Sugar().Errorf("Fatal error config file: %s \n", err)
	}

	cli.Run("p2", "personally identifying information (PII) masker",
		cli.Command(genRecordsE,
			"gen -c <count> -f <file>",
			"create new set of customer records and save to file",
			cli.CommandOptionFunc(func(cmd *cobra.Command) {
				cmd.Flags().IntP("count", "c", 1, "count of customers to create and save")
				cmd.Flags().StringP("file", "f", "", "file with encrypted customer record")
			}),
		),
		cli.Command(readCustomerE,
			"read",
			"read customers from file",
			cli.CommandOptionFunc(func(cmd *cobra.Command) {
				cmd.Flags().StringP("file", "f", "", "file with encrypted customer record")
			}),
		),
		cli.Command(decryptCustomerE,
			"decrypt",
			"decrypt a file with customer data",
			cli.CommandOptionFunc(func(cmd *cobra.Command) {
				cmd.Flags().StringP("file", "f", "", "file with encrypted customer record")
			}),
		),
		cli.Command(createKeyE,
			"key <key-name>",
			"create a new RSA keypair",
		),
		cli.CommandOptionFunc(func(cmd *cobra.Command) {
			cmd.PersistentFlags().StringP("key-name", "n", "", "name of the private key to create")
		}),
	)
}

func createKeyE(cmd *cobra.Command, args []string) error {

	key := cmd.Flag("key-name")
	zlog.Debug("key", zap.String("key-name", key.Value.String()))

	encryption.Createkey(key.Value.String())
	zlog.Info("created keypair", zap.String("key-name", key.Value.String()))
	return nil
}

func genRecordsE(cmd *cobra.Command, args []string) error {

	count := cmd.Flag("count")
	zlog.Debug("count", zap.String("count", count.Value.String()))
	countInt, err := strconv.Atoi(count.Value.String())
	cli.NoError(err, "cannot convert count parameter to integer")

	records := make([]pkg.Record, countInt)

	for i := 0; i < countInt; i++ {
		customer := pkg.NewCustomer()
		records[i], err = pkg.NewRecord(customer, cmd.Flag("key-name").Value.String())
		if err != nil {
			zlog.Fatal("cannot generate record", zap.Error(err))
		}
		fmt.Println("New: " + strconv.Itoa(i) + " of " + strconv.Itoa(countInt) + ": " + customer.LastName + ", " + customer.FirstName)
	}

	recordsStr, err := json.MarshalIndent(records, "", "  ")
	cli.NoError(err, "cannot marshall customer to string")

	err = ioutil.WriteFile(cmd.Flag("file").Value.String(), recordsStr, 0644)
	cli.NoError(err, "cannot write file")

	return nil
}

func readCustomerE(cmd *cobra.Command, args []string) error {

	// key := cmd.Flag("key-name")

	file, err := ioutil.ReadFile(cmd.Flag("file").Value.String())
	cli.NoError(err, "cannot read file")

	records := []pkg.Record{}
	err = json.Unmarshal([]byte(file), &records)
	cli.NoError(err, "cannot unmarshal records")

	for i, record := range records {

		// customerBytes := new(bytes.Buffer)
		// 	json.NewEncoder(customerBytes).Encode(customer)

		// 	aesKey := encryption.NewAesEncryptionKey()
		// 	aesEncryptedData, err := encryption.AesEncrypt(customerBytes.Bytes(), aesKey)
		// 	cli.NoError(err, "error with AES encryption")

		// 	msg := newMessage()
		// 	encryptedAesKey, err := encryption.RsaEncrypt(keyName.Value.String(), aesKey[:])
		// 	cli.NoError(err, "error with RSA encryption")

		// 	msg.Payload["EncryptedPayload"] = aesEncryptedData
		// 	msg.Payload["EncryptedAESKey"] = encryptedAesKey

		// 	msgS, err := json.MarshalIndent(msg, "", "  ")
		// 	cli.NoError(err, "cannot marshall customer to string")

		// 	err = ioutil.WriteFile("x-"+strings.ToLower(customer.LastName)+"-"+strings.ToLower(customer.FirstName)+".json", msgS, 0644)
		// 	cli.NoError(err, "cannot write file")

		fmt.Println("Read: " + strconv.Itoa(i) + " of " + strconv.Itoa(len(records)) + ": " + record.Customer.LastName + ", " + record.Customer.FirstName)
		// 	fmt.Println()
	}

	return nil
}

func decryptCustomerE(cmd *cobra.Command, args []string) error {

	// file, err := ioutil.ReadFile(cmd.Flag("file").Value.String())
	// cli.NoError(err, "cannot read file")

	//  := Message{}
	// err = json.Unmarshal([]byte(file), &msg)msg
	// cli.NoError(err, "cannot unmarshal file")

	// keyName := cmd.Flag("key-name").Value.String()

	// aesKey, err := encryption.RsaDecrypt(keyName, msg.Payload["EncryptedAESKey"])
	// cli.NoError(err, "cannot decrypt AES key using RSA")

	// plaintext, err := encryption.AesDecrypt(msg.Payload["EncryptedPayload"], &aesKey)
	// cli.NoError(err, "cannot decrypt payload with AES")

	// fmt.Println("Decrypted message using key: ", keyName, "\n", string(plaintext))
	return nil
}
