package dkim

import (
	"fmt"
)

const dnsRawRSAPublicKey = "v=DKIM1; p=MIGJAoGBALVI635dLK4cJJAH3Lx6upo3X/L" +
	"m1tQz3mezcWTA3BUBnyIsdnRf57aD5BtNmhPrYYDlWlzw3" +
	"UgnKisIxktkk5+iMQMlFtAS10JB8L3YadXNJY+JBcbeSi5" +
	"TgJe4WFzNgW95FWDAuSTRXSWZfA/8xjflbTLDx0euFZOM7" +
	"C4T0GwLAgMBAAE="

const dnsPublicKey = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" +
	"KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" +
	"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v" +
	"/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" +
	"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"

const dnsEd25519PublicKey = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

const dnsShortPublicKey = "v=DKIM1; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALBNzlc7mGoSwWAsRGkBZpmLv4qJncyLJuRGmmeC5X0hbK/dQMZ/UM60btRY6aBnOab8t544RdIs6aH9dWYhGikCAwEAAQ=="

func init() {
	queryMethods["dns/txt"] = queryTest
}

func queryTest(domain, selector string, options *VerifyOptions) (*queryResult, error) {
	record := selector + "._domainkey." + domain
	switch record {
	case "brisbane._domainkey.example.com", "brisbane._domainkey.example.org", "test._domainkey.football.example.com":
		return parsePublicKey(dnsPublicKey, 0)
	case "newengland._domainkey.example.com":
		return parsePublicKey(dnsRawRSAPublicKey, 0)
	case "brisbane._domainkey.football.example.com":
		return parsePublicKey(dnsEd25519PublicKey, 0)
	case "short._domainkey.example.com":
		return parsePublicKey(dnsShortPublicKey, 512)
	}
	return nil, fmt.Errorf("unknown test DNS record %v", record)
}
