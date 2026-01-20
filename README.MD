### Modified ASN.1 DER parcer from Go stdlib, for support BER reality  

### all modification only for Unmarshaling 

## Features
- Long Form Lengths (`0x81 00`, `0x83 00FFFE`)
- Indefinite Length (`0x80 ... 00 00`)
- Nested Indefinite (3 levels)
- Primitive Indefinite = BLOCKED (security)

**Added extra 2 function (need for SNMP data manipulation)**

 - FindSNMPv3AuthParamsOffset(data []byte) (offset, len int, err error)
 - ExtractDataWOTagAndLen(data []byte, offset int) ([]byte, error)