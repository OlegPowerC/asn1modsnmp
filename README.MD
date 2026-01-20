### Modified ASN.1 DER parcer from Go stdlib, for support BER reality  
[![Go Report Card](https://goreportcard.com/badge/github.com/OlegPowerC/powersnmpv3)](https://goreportcard.com/report/github.com/OlegPowerC/asn1modsnmp)
[![GoDoc](https://godoc.org/github.com/OlegPowerC/powersnmpv3?status.svg)](https://godoc.org/github.com/OlegPowerC/asn1modsnmp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### all modification only for Unmarshaling 

## Features
- Long Form Lengths (`0x81 00`, `0x83 00FFFE`)
- Indefinite Length (`0x80 ... 00 00`)
- Nested Indefinite (3 levels)
- Primitive Indefinite = BLOCKED (security)

**Added extra 2 function (need for SNMP data manipulation)**

 - FindSNMPv3AuthParamsOffset(data []byte) (offset, len int, err error)
 - ExtractDataWOTagAndLen(data []byte, offset int) ([]byte, error)