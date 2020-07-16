package transport

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
)

// Supported log events
// https://quiclog.github.io/internet-drafts/draft-marx-qlog-event-definitions-quic-h3.html
const (
	LogEventPacketReceived = "packet_received"
	LogEventPacketSent     = "packet_sent"
	LogEventPacketDropped  = "packet_dropped"
	LogEventFrameProcessed = "frame_processed"
)

// LogEvent is event sent by connection
type LogEvent struct {
	Type   string
	Fields []LogField
}

func newLogEvent(tp string) LogEvent {
	return LogEvent{
		Type:   tp,
		Fields: make([]LogField, 0, 8),
	}
}

func (s *LogEvent) addField(k string, v interface{}) {
	s.Fields = append(s.Fields, newLogField(k, v))
}

func (s LogEvent) String() string {
	buf := bytes.Buffer{}
	buf.WriteString("type=")
	buf.WriteString(s.Type)
	for _, f := range s.Fields {
		buf.WriteString(" ")
		buf.WriteString(f.String())
	}
	return buf.String()
}

// LogField represents a number or string value.
type LogField struct {
	Key string // Field name
	Str string // String value
	Num uint64 // Number value
}

func newLogField(key string, val interface{}) LogField {
	s := LogField{
		Key: key,
	}
	switch val := val.(type) {
	case int:
		s.Num = uint64(val)
	case int8:
		s.Num = uint64(val)
	case int16:
		s.Num = uint64(val)
	case int32:
		s.Num = uint64(val)
	case int64:
		s.Num = uint64(val)
	case uint:
		s.Num = uint64(val)
	case uint8:
		s.Num = uint64(val)
	case uint16:
		s.Num = uint64(val)
	case uint32:
		s.Num = uint64(val)
	case uint64:
		s.Num = val
	case string:
		s.Str = val
	case []byte:
		s.Str = hex.EncodeToString(val)
	case []uint32:
		b := make([]byte, 0, 32)
		b = append(b, '[')
		for i, v := range val {
			if i > 0 {
				b = append(b, ',')
			}
			b = strconv.AppendUint(b, uint64(v), 10)
		}
		b = append(b, ']')
		s.Str = string(b)
	default:
		panic("unsupported type for log field")
	}
	return s
}

func (s LogField) String() string {
	if s.Str == "" {
		return fmt.Sprintf("%s=%d", s.Key, s.Num)
	}
	return fmt.Sprintf("%s=%s", s.Key, s.Str)
}

func logEventPacket(s *LogEvent, p *packet) {
	s.addField("packet_type", p.typ.String())
	// Header
	if p.header.version > 0 {
		s.addField("version", p.header.version)
	}
	if len(p.header.dcid) > 0 {
		s.addField("dcid", p.header.dcid)
	}
	if len(p.header.scid) > 0 {
		s.addField("scid", p.header.scid)
	}
	if p.packetNumber > 0 {
		s.addField("packet_number", p.packetNumber)
	}
	if p.payloadLen > 0 {
		s.addField("payload_length", p.payloadLen)
	}
	// Additional info
	if len(p.supportedVersions) > 0 {
		s.addField("supported_versions", p.supportedVersions)
	}
	if len(p.token) > 0 {
		s.addField("stateless_reset_token", p.token)
	}
}

func logEventFrame(s *LogEvent, typ uint64) {
	s.addField("frame_type", typ)
}
