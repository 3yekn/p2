package pkg

import (
	"encoding/json"
	"log"

	"github.com/bxcodec/faker"
	"github.com/dfuse-io/logging"
	"go.uber.org/zap"
)

var zlog *zap.Logger

func init() {
	logging.Register("github.com/dappdever/p2/pkg", &zlog)
}

// GetCustomer ...
func NewCustomer() Customer {
	var privatePayload Customer
	err := faker.FakeData(&privatePayload)

	if err != nil {
		log.Println("Cannot generate fake data: ", err)
	}
	return privatePayload
}

// Customer ...
type Customer struct {
	RecordID         string `faker:"uuid_hyphenated" json:"uuid"`
	FirstName        string `faker:"first_name" json:"first_name"`
	LastName         string `faker:"last_name" json:"last_name"`
	DOB              string `faker:"date" json:"date"`
	CreditCardNumber string `faker:"cc_number" json:"cc_number"`
	CreditCardType   string `faker:"cc_type" json:"cc_type"`
	Email            string `faker:"email" json:"email"`
	TimeZone         string `faker:"timezone" json:"timezone"`
	AmountDue        string `faker:"amount_with_currency" json:"amount_due"`
	PhoneNumber      string `faker:"phone_number" json:"phone_number"`
	SafeWord         string `faker:"word" json:"safe_word"`
	LastScan         string `faker:"timestamp" json:"last_login"`
}

func (c *Customer) String() string {
	cS, err := json.Marshal(c)
	if err != nil {
		zlog.Error("cannot convert customer to string", zap.Error(err))
		return "conversion of string failed"
	}
	return string(cS)
}
