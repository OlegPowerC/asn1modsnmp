package asn1modsnmp

import (
	"encoding/asn1"
	"testing"
)

func TestParseTagAndLength(t *testing.T) {
	t.Log("Tag: 0x05, Len form: short, Len value: 0")
	bytestfortest1 := []byte{0x05, 00}
	rtd, ofi, err := parseTagAndLength(bytestfortest1, 0)
	t.Log("Len is:", rtd.length, "offsett is:", ofi)
	if err != nil {
		t.Error("Error:", err)
	}
	if rtd.length != 0 || ofi != 2 {
		t.Errorf("Error parsing tag and length, expected len: 0, got: %d, expexted offsett 2: got: %d", rtd.length, ofi)
	}

	t.Log("Tag: 0x05, Len form: long, Len value: 0x81,0x00")
	bytestfortest2 := []byte{0x05, 0x81, 0x00}
	rtd, ofi, err = parseTagAndLength(bytestfortest2, 0)
	t.Log("Len is:", rtd.length, "offsett is:", ofi)
	if err != nil {
		t.Error("Error:", err)
	}
	if rtd.length != 0 || ofi != 3 {
		t.Errorf("Error parsing tag and length, expected len: 0, got: %d, expexted offsett 3: got: %d", rtd.length, ofi)
	}

	t.Log("Tag: 0x12, Len form: long, Len value: 0x83,0x00,0xff,0xfe")
	bytestfortest3 := []byte{0x12, 0x83, 0x00, 0xff, 0xfe}
	rtd, ofi, err = parseTagAndLength(bytestfortest3, 0)
	t.Log("Len is:", rtd.length, "offsett is:", ofi)
	if err != nil {
		t.Error("Error:", err)
	}
	if rtd.length != 65534 || ofi != 5 {
		t.Errorf("Error parsing tag and length, expected len: 65534, got: %d, expexted offsett 5: got: %d", rtd.length, ofi)
	}

	t.Log("Tag: 0x12, Len form: Undefined, Len value: 0x80. Invalid!")
	bytestfortest4 := []byte{0x12, 0x80, 0x1a, 0xff, 0xfe, 0x00, 0x00}
	rtd, ofi, err = parseTagAndLength(bytestfortest4, 0)
	t.Log("Len is:", rtd.length, "offsett is:", ofi)
	if err == nil {
		t.Log("Len is:", rtd.length, "offsett is:", ofi)
		t.Error("Error: expected  indefinite length found in primitive type, but err=nil")
	} else {
		t.Log(err)
	}

	t.Log("Tag: 0x30, Len form: Undefined, Len value: 0x80, No end 0x00, 0x00")
	bytestfortest5 := []byte{0x30, 0x80, 0x06, 0x03, 0xfe, 0x00, 0x02}
	rtd, ofi, err = parseTagAndLength(bytestfortest5, 0)
	if err == nil {
		t.Log("Len is:", rtd.length, "offsett is:", ofi)
		t.Error("Error: expexted indefinite length: end-of-contents not foun but err = nil", err)
	} else {
		t.Log(err)
	}
}

type cmdata struct {
	Oid  ObjectIdentifier
	Nval RawValue
}

type cmdataa1 struct {
	Oid  asn1.ObjectIdentifier
	Nval asn1.RawValue
}

type cmdataall struct {
	ExtData cmdata
	Oid     ObjectIdentifier
}

type cmdataalla1 struct {
	ExtData cmdataa1
	Oid     asn1.ObjectIdentifier
}

type cmdataall2 struct {
	ExtData cmdataall
	Oid     ObjectIdentifier
}

type cmdataall2a1 struct {
	ExtData cmdataalla1
	Oid     asn1.ObjectIdentifier
}

type rawteststr struct {
	Rawdata RawValue
	Oid     ObjectIdentifier
}

func TestUnmarshal(t *testing.T) {
	var testtr cmdata
	var testtrstdlib cmdataa1
	//SEQUENCE, второй объект (null value0 длина в long форме
	umst := []byte{0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, 0x05, 0x81, 0x00}
	t.Log("--- MOD---")
	_, umerr := Unmarshal(umst, &testtr)
	t.Log(testtr)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	t.Log("--- STDLIB---")
	testtrstdlib = cmdataa1{}
	_, umerrstdlib := asn1.Unmarshal(umst, &testtrstdlib)

	if umerrstdlib == nil {
		t.Log(testtrstdlib)
		t.Error("expected superfluous leading zeros in length, but err=nil")
	} else {
		t.Log(umerrstdlib)
	}
	t.Log("\r\n\r\n")

	testtr = cmdata{}
	testtrstdlib = cmdataa1{}
	//SEQUENCE, второй объект (null value0 длина в short форме
	umst = []byte{0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, 0x05, 0x00}
	t.Log("--- MOD---")
	_, umerr = Unmarshal(umst, &testtr)
	t.Log(testtr)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	t.Log("--- STDLIB---")
	_, umerrstdlib = asn1.Unmarshal(umst, &testtrstdlib)
	t.Log(testtrstdlib)
	if umerrstdlib != nil {
		t.Error(umerrstdlib.Error())
	}
	t.Log("\r\n\r\n")

	testtr = cmdata{}
	testtrstdlib = cmdataa1{}

	//SEQUENCE, длина указана как infinite
	umst = []byte{0x30, 0x80, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, 0x05, 0x00, 00, 00}
	t.Log("--- MOD---")
	_, umerr = Unmarshal(umst, &testtr)
	t.Log(testtr)
	if umerr != nil {
		t.Error(umerr.Error())
	}
	t.Log("--- STDLIB---")
	_, umerrstdlib = asn1.Unmarshal(umst, &testtrstdlib)
	if umerrstdlib == nil {
		t.Error("expected indefinite length found (not DER), but err=nil")
	} else {
		t.Log(umerrstdlib)
	}
	t.Log("\r\n\r\n")

	testtr = cmdata{}
	testtrstdlib = cmdataa1{}

	umst = []byte{0x30, 0x10, 0x06, 0x82, 0x00, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, 0x05, 0x00}
	t.Log("--- MOD---")
	_, umerr = Unmarshal(umst, &testtr)
	t.Log(testtr)
	if umerr != nil {
		t.Error(umerr.Error())
	}
	t.Log("--- STDLIB---")
	_, umerrstdlib = asn1.Unmarshal(umst, &testtrstdlib)

	if umerrstdlib == nil {
		t.Error("expected superfluous leading zeros in lengt, but err=nil")
	} else {
		t.Log(umerrstdlib.Error())
	}
	t.Log("\r\n\r\n")

	// Тест 1: Внешний indefinite, внутренний indefinite
	var exd cmdataall
	var exdstdlib cmdataalla1

	umst = []byte{
		0x30, 0x80, // Внешний SEQUENCE indefinite
		0x30, 0x80, // Внутренний SEQUENCE indefinite (ExtData)
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // OID
		0x05, 0x00, // NULL
		0x00, 0x00, // end внутреннего SEQUENCE
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // второй OID
		0x00, 0x00, // end внешнего SEQUENCE
	}
	t.Log("--- MOD---")
	_, umerr = Unmarshal(umst, &exd)
	t.Log(exd)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	t.Log("--- STDLIB---")
	_, umerrstdlib = asn1.Unmarshal(umst, &exdstdlib)
	if umerrstdlib == nil {
		t.Error("expected indefinite length found (not DER), but err=nil")
	} else {
		t.Log(umerrstdlib)
	}
	t.Log("\r\n\r\n")

	exd = cmdataall{}
	exdstdlib = cmdataalla1{}
	// Тест 2: Внешний definite (length=30), внутренний indefinite
	umst = []byte{
		0x30, 0x1e, // Внешний SEQUENCE definite, length=30
		0x30, 0x80, // Внутренний SEQUENCE indefinite (ExtData)
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // OID (12 байт)
		0x05, 0x00, // NULL (2 байта)
		0x00, 0x00, // end внутреннего (2 байта)
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // второй OID (12 байт)
	}
	t.Log("--- MOD---")

	exd = cmdataall{}
	_, umerr = Unmarshal(umst, &exd)
	t.Log(exd)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	t.Log("--- STDLIB---")
	_, umerrstdlib = asn1.Unmarshal(umst, &exdstdlib)
	if umerrstdlib == nil {
		t.Error("expected indefinite length found (not DER), but err=nil")
	} else {
		t.Log(umerrstdlib)
	}
	t.Log("\r\n\r\n")

	var exd2 cmdataall2
	var exd2stdlib cmdataall2a1
	// Тест New: Внешний indefinite, внутренний indefinite, внутренний indefinite
	umst = []byte{
		0x30, 0x80, // Внешний SEQUENCE indefinite
		0x30, 0x80, // Внутренний1 SEQUENCE indefinite
		0x30, 0x80, // Внутренний2 SEQUENCE definite, indefinite
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x0, 0x00, 0x09, 0x01, 0x04, 0x62, // OID (12 байт)
		0x05, 0x00, // NULL (2 байта)
		0x00, 0x00, // end Внутренний2
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // второй OID (12 байт)
		0x00, 0x00, // end Внутренний2 SEQUENCE
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // второй OID (12 байт)
		0x00, 0x00, // end внешнего SEQUENCE
	}
	t.Log("--- MOD---")
	_, umerr = Unmarshal(umst, &exd2)
	t.Log(exd2)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	t.Log("--- STDLIB---")
	_, umerrstdlib = asn1.Unmarshal(umst, &exd2stdlib)
	if umerrstdlib == nil {
		t.Error("expected indefinite length found (not DER), but err=nil")
	} else {
		t.Log(umerrstdlib)
	}
	t.Log("\r\n\r\n")

	exd2 = cmdataall2{}
	exd2stdlib = cmdataall2a1{}
	// Тест 4: Внешний indefinite, внутренний definite (length=14)
	umst = []byte{
		0x30, 0x80, // Внешний SEQUENCE indefinite
		0x30, 0x0e, // Внутренний SEQUENCE definite, length=14
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x0, 0x00, 0x09, 0x01, 0x04, 0x62, // OID (12 байт)
		0x05, 0x00, // NULL (2 байта)
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // второй OID (12 байт)
		0x00, 0x00, // end внешнего SEQUENCE
	}
	t.Log("--- MOD---")
	exd = cmdataall{}
	_, umerr = Unmarshal(umst, &exd)
	t.Log(exd)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	t.Log("--- STDLIB---")
	_, umerrstdlib = asn1.Unmarshal(umst, &exd2stdlib)
	if umerrstdlib == nil {
		t.Error("expected indefinite length found (not DER), but err=nil")
	} else {
		t.Log(umerrstdlib)
	}
	t.Log("\r\n\r\n")

}

func TestParceToRawData(t *testing.T) {
	var exd2 rawteststr
	// Тест New: Внешний indefinite, внутренний indefinite, внутренний indefinite
	umst := []byte{
		0x30, 0x80, // Внешний SEQUENCE indefinite
		0x30, 0x80, // Внутренний1 SEQUENCE indefinite
		0x30, 0x80, // Внутренний2 SEQUENCE definite, indefinite
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x0, 0x00, 0x09, 0x01, 0x04, 0x62, // "Это OID во внутреннем2 SEQUENCE"
		0x05, 0x00, // NULL (2 байта) во внутреннем2 SEQUENCE
		0x00, 0x00, // end Внутренний2
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // "Это OID во внутреннем1 SEQUENCE"
		0x00, 0x00, // end Внутренний1 SEQUENCE
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x62, // Это OID во внешнем SEQUENCE
		0x00, 0x00, // end внешнего SEQUENCE
	}
	t.Log("--- TWO SEQUECE TO RAW---")
	_, umerr := Unmarshal(umst, &exd2)
	t.Log(exd2)
	t.Log(exd2.Rawdata)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	var exdinside1 rawteststr
	t.Log("--- TWO SEQUECE1 TO RAW---")
	_, umerr = Unmarshal(exd2.Rawdata.FullBytes, &exdinside1)
	t.Log(exdinside1)
	t.Log(exdinside1.Rawdata)
	if umerr != nil {
		t.Error(umerr.Error())
	}

	var exdinside2 cmdata
	t.Log("--- TWO SEQUECE2 TO OID AND NULL---")
	_, umerr = Unmarshal(exdinside1.Rawdata.FullBytes, &exdinside2)
	t.Log(exdinside2)
	t.Log(exdinside2.Oid)
	t.Log(exdinside2.Nval)
	if umerr != nil {
		t.Error(umerr.Error())
	}

}
func TestFiniteLoop(t *testing.T) {
	data := []byte{0x30, 0x06, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00}
	var s struct{}
	_, err := asn1.Unmarshal(data, &s)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(s)
}

func TestIndefiniteLoop(t *testing.T) {
	data := []byte{0x30, 0x80, // SEQUENCE indefinite
		0x05, 0x00, // NULL (length=0)
		0x05, 0x00, // NULL (length=0)
		0x05, 0x00} // NULL (length=0)

	var s struct{}
	_, err := Unmarshal(data, &s)
	if err == nil {
		t.Fatal("Expected error, got success (infinite loop!)")
	}
	t.Log(err)
}

type NdataFtest struct {
	name string
	data []byte
}

func TestASN1Attacks(t *testing.T) {
	tests := []NdataFtest{
		{"self_ref_tag", []byte{0x30, 0x82, 0x00, 0x10, 0x30, 0x82, 0xFF, 0xFF}},
		{"infinite_tag", []byte{0x1F, 0x81, 0xFF, 0x30, 0x80}},
		{"empty_seq_spam", []byte{0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s struct{}
			var s1 struct{}
			_, err := Unmarshal(tt.data, &s)
			if err == nil {
				t.Log(s)
				t.Log("Attack passed!")
			}
			t.Logf("%s: BLOCKED %v", tt.name, err)

			_, err2 := asn1.Unmarshal(tt.data, &s1)
			if err2 == nil {
				t.Log(s1)
				t.Log("Attack passed!")
			}
			t.Logf("%s: BLOCKED %v", tt.name, err2)
		})
	}
}
