package echonetlite

import (
	"net"

	"go.uber.org/zap"
)

// TODO
// type PropertyData []interface{}

// FrameFormat expresses ECHONET Lite payload
// OPCG and VarGroupsG is only used when ESV is 0x6E or 0x5E or 0x7E
type FrameFormat struct {
	EHD1       uint8          // Default 0x10
	EHD2       uint8          // Default 0x81
	TID        uint16         // Transaction ID
	SEOJ       [3]uint8       // Target Object Code
	DEOJ       [3]uint8       // Sourse Object Code
	ESV        uint8          // ECHONET Lite Service code
	OPC        uint8          // The count of VarGroups
	VarGroups  []VarByteGroup // Group of EPC, PDC and EDT
	OPCG       uint8          // Normally, only used when ESV&0x0F == 0xE. The count of VarGroupsG
	VarGroupsG []VarByteGroup // Group of EPC, PDC and EDT
}

// VarByteGroup is a part of FrameFormat
type VarByteGroup struct {
	EPC uint8
	PDC uint8
	EDT []uint8
}

// Instance expresses ECHONET Lite instance
type Instance struct {
	// ClassCode is ECHONET Lite Class Code
	// For example, if the instance is Air Conditonar, Class Code is [3]uint8{0x01, 0x30, 0xNN}. (0xNN is any number)
	ClassCode [3]uint8

	ClassName string

	// Props are the properties the instance has
	Props   []Property
	release string
}

// Property includes the specification of property
type Property struct {
	// EPC is property code
	// if Property is "Operating status", EPC is 0x80
	EPC uint8

	PropertyName string

	// Get, Set and Inf is the access rule specification
	// the values are below
	//		required			: necessary to implement the access rule
	//		optional			: the implementaion is optional
	//		notApplicable	: the implementaion forbidden
	Get string
	Set string
	Inf string

	// ImplementGet, ImplementSet and ImplementSet is the status of that the target device implement the access rule
	ImplementGet bool
	ImplementSet bool
	ImplementInf bool
	Note         string

	// Data is proparty data is used EDT as usual
	// the value types are below
	//		Number, State, Level, Object, Array, Bitmap, NumericValues, DateTime, Raw
	//
	// They are apply for data format in JSON file (class.json)
	// and their names match the keys in class.json.
	Data []interface{}
}

type enumber struct {
	edt      int64
	state    string
	readOnly bool
}

type Number struct {
	format     string
	minimum    int64
	maximum    int64
	unit       string
	multipleOf float64
	coeff      []uint8
	enum       []int64
}

type State struct {
	size int64
	enum []enumber
}

type Level struct {
	base    string
	maximum uint64
}

type Raw struct {
	minSize int64
	maxSize int64
}

type ElObject struct {
	name string
	data []interface{}
}

type Object struct {
	element []ElObject
}

type Array struct {
	itemSize int64
	minItems int64
	maxItems int64
	data     []interface{}
}

type ElBitmap struct {
	name         string
	descriptions string
	index        int64
	bitmask      uint64
	value        []interface{}
}

type Bitmap struct {
	size    int64
	bitmaps []ElBitmap
}

type NumericValues struct {
	size int64
	enum []NumericValue
}

type NumericValue struct {
	edt   int64
	value float64
}

type DateTime struct {
	size int64
}

// Auditor is ECHONET Lite test struct
type Auditor struct {
	SrcNodes  []Node // Tester ECHONET Lite nodes
	DistNodes []Node // Target ECHONET Lite nodes
	logger    *zap.Logger
}

// Node has the imformation of ECHONET Lite node
type Node struct {
	ip        net.IP
	connSend  net.Conn
	connRecv  *net.UDPConn
	Instances []Instance // Instances in Node
	logger    *zap.Logger
}

type SettingECHONET struct {
	Ips TestIps
}

type TestIps struct {
	ip []string
}
