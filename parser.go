package main

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type ParserFunc func(data string, msg *dns.Msg) error

var sectionParsers = map[string]ParserFunc{
	"HEADER":     parseDigHeader,
	"FLAGS":      parseDigFlags,
	"QUESTION":   parseDigQuestion,
	"ANSWER":     parseDigAnswer,
	"ADDITIONAL": parseDigAdditional,
}

func ParseDigOutput(data string) ([]*dns.Msg, error) {
	const (
		headerSection     = ";; ->>HEADER<<- "
		flagsSection      = ";; flags: "
		questionSection   = ";; QUESTION SECTION:"
		answerSection     = ";; ANSWER SECTION:"
		additionalSection = ";; ADDITIONAL SECTION:"
	)

	var messages []*dns.Msg

	m := &dns.Msg{
		Question: []dns.Question{},
		Answer:   []dns.RR{},
		Extra:    []dns.RR{},
	}
	s := bufio.NewScanner(strings.NewReader(data))

	currentParser := (ParserFunc)(nil)

	for s.Scan() {
		line := s.Text()

		switch {
		case strings.HasPrefix(line, headerSection):
			currentParser = sectionParsers["HEADER"]
			if m.Id > 0 {
				messages = append(messages, m)
				m = &dns.Msg{}
			}
		case strings.HasPrefix(line, flagsSection):
			currentParser = sectionParsers["FLAGS"]
		case strings.HasPrefix(line, questionSection):
			currentParser = sectionParsers["QUESTION"]
			continue
		case strings.HasPrefix(line, answerSection):
			currentParser = sectionParsers["ANSWER"]
			continue
		case strings.HasPrefix(line, additionalSection):
			currentParser = sectionParsers["ADDITIONAL"]
			continue
		}

		if currentParser != nil {
			if err := currentParser(line, m); err != nil {
				return nil, fmt.Errorf("failed to parse section: %v", err)
			}
		}
	}

	if m.Id > 0 {
		messages = append(messages, m)
	}

	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %v", err)
	}

	return messages, nil
}

// parseHeader sets header values on the provided *dns.Msg by parsing data:
// ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
func parseDigHeader(data string, m *dns.Msg) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}

	headers := strings.Split(data[13:], ", ")
	for _, field := range headers {
		keyValue := strings.SplitN(field, ": ", 2)
		if len(keyValue) != 2 {
			continue // skip malformed entries
		}

		key, value := strings.TrimSpace(keyValue[0]), strings.TrimSpace(keyValue[1])

		switch key {
		case "opcode":
			m.Opcode = invertMap(dns.OpcodeToString)[value]
		case "status":
			m.Rcode = invertMap(dns.RcodeToString)[value]
		case "id":
			id, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return fmt.Errorf("invalid ID value '%s': %w", value, err)
			}
			m.Id = uint16(id)
		}
	}

	return nil
}

// parseFlgs set flags on the provided *dns.Msg by parsing data:
// ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
func parseDigFlags(data string, m *dns.Msg) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}

	data, _, _ = strings.Cut(data[10:], ";")
	data = strings.TrimSpace(data)

	for _, flag := range strings.Fields(data) {
		switch flag {
		case "qr":
			m.Response = true
		case "rd":
			m.RecursionDesired = true
		case "ra":
			m.RecursionAvailable = true
		}
	}

	return nil
}

// parseQuestion sets values on the provided *dns.Msg by parsing data:
// ;; QUESTION SECTION:
// ;example.com.	IN	 A
func parseDigQuestion(data string, m *dns.Msg) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}

	data = strings.TrimLeft(data, ";")

	fields := strings.Fields(data)

	name := fields[0]
	qClass := invertMap(dns.ClassToString)[fields[1]]
	qType := invertMap(dns.TypeToString)[fields[2]]

	m.Question = append(m.Question, dns.Question{
		Name:   name,
		Qtype:  qType,
		Qclass: qClass,
	})

	return nil
}

// parseDigAnswer sets values on the provided *dns.Msg by parsing data:
// ;; ANSWER SECTION:
// example.com.	30	IN	A	10.0.0.1
func parseDigAnswer(data string, m *dns.Msg) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}

	rr, err := dns.NewRR(data)
	if err != nil {
		return err
	}

	m.Answer = append(m.Answer, rr)

	return nil
}

// parseDigAdditional sets values on the provided *dns.Msg by parsing data:
// ;; ADDITIONAL SECTION:
// maas.  30  IN  A  127.0.0.1
func parseDigAdditional(data string, m *dns.Msg) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}

	rr, err := dns.NewRR(data)
	if err != nil {
		return err
	}

	m.Extra = append(m.Extra, rr)

	return nil
}

func invertMap[K, V comparable](m map[K]V) map[V]K {
	inv := make(map[V]K, len(m))

	for k, v := range m {
		inv[v] = k
	}

	return inv
}
