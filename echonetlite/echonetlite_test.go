package echonetlite

import (
	"strings"
	"testing"
)

type inputData []byte

func Test_parser(t *testing.T) {
	normalTestCase := [...]inputData{
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x01, 0x80, 0x01, 0x30},
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x03, 0x80, 0x01, 0x30, 0x80, 0x01, 0x31, 0x80, 0x01, 0x30},
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x03, 0x80, 0x01, 0x30, 0x80, 0x00, 0x80, 0x01, 0x30},
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x03, 0x80, 0x02, 0x30, 0x31, 0x80, 0x01, 0x30, 0x80, 0x05, 0x30, 0x31, 0x32, 0x33, 0x34},
	}
	normalTestExpect := [...]FrameFormat{
		{
			EHD1: 0x10,
			EHD2: 0x81,
			TID:  0x0000,
			SEOJ: [3]uint8{0x05, 0xff, 0x01},
			DEOJ: [3]uint8{0x01, 0x30, 0x01},
			ESV:  0x60,
			OPC:  0x01,
			VarGroups: []VarByteGroup{
				{
					EPC: 0x80,
					PDC: 0x01,
					EDT: []uint8{0x30},
				},
			},
		},
		{
			EHD1: 0x10,
			EHD2: 0x81,
			TID:  0x0000,
			SEOJ: [3]uint8{0x05, 0xff, 0x01},
			DEOJ: [3]uint8{0x01, 0x30, 0x01},
			ESV:  0x60,
			OPC:  0x03,
			VarGroups: []VarByteGroup{
				{
					EPC: 0x80,
					PDC: 0x01,
					EDT: []uint8{0x30},
				},
				{
					EPC: 0x80,
					PDC: 0x01,
					EDT: []uint8{0x31},
				},
				{
					EPC: 0x80,
					PDC: 0x01,
					EDT: []uint8{0x30},
				},
			},
		},
		{
			EHD1: 0x10,
			EHD2: 0x81,
			TID:  0x0000,
			SEOJ: [3]uint8{0x05, 0xff, 0x01},
			DEOJ: [3]uint8{0x01, 0x30, 0x01},
			ESV:  0x60,
			OPC:  0x03,
			VarGroups: []VarByteGroup{
				{
					EPC: 0x80,
					PDC: 0x02,
					EDT: []uint8{0x30, 0x31},
				},
				{
					EPC: 0x80,
					PDC: 0x01,
					EDT: []uint8{0x30},
				},
				{
					EPC: 0x80,
					PDC: 0x05,
					EDT: []uint8{0x30, 0x31, 0x32, 0x33, 0x34},
				},
			},
		},
	}
	for index, tc := range normalTestCase {
		actual, err := parser(tc)
		if err != nil {
			t.Errorf("Return value is not nil from function parser: %w", err)
		} else {
			if actual.EHD1 != normalTestExpect[index].EHD1 {
				t.Errorf("EHD1 value is return parser(tc) => %v, want %v", actual.EHD1, normalTestExpect[index].EHD1)
			}
			if actual.EHD2 != normalTestExpect[index].EHD2 {
				t.Errorf("EHD2 value is return parser(tc) => %v, want %v", actual.EHD2, normalTestExpect[index].EHD2)
			}
			if actual.TID != normalTestExpect[index].TID {
				t.Errorf("TID value is return parser(tc) => %v, want %v", actual.TID, normalTestExpect[index].TID)
			}
			for i, v := range normalTestExpect[index].SEOJ {
				if v != actual.SEOJ[i] {
					t.Errorf("SEOJ value is return parser(tc) => %v, want %v", v, normalTestExpect[index].SEOJ[i])
				}
			}
			for i, v := range normalTestExpect[index].DEOJ {
				if v != actual.DEOJ[i] {
					t.Errorf("DEOJ value is return parser(tc) => %v, want %v", v, normalTestExpect[index].DEOJ[i])
				}
			}
			if actual.ESV != normalTestExpect[index].ESV {
				t.Errorf("ESV value is return parser(tc) => %v, want %v", actual.ESV, normalTestExpect[index].ESV)
			}
			if actual.OPC != normalTestExpect[index].OPC {
				t.Errorf("OPC value is return parser(tc) => %v, want %v", actual.OPC, normalTestExpect[index].OPC)
			}
			for i := 0; i < int(normalTestExpect[index].OPC); i++ {
				if actual.VarGroups[i].EPC != normalTestExpect[index].VarGroups[i].EPC {
					t.Errorf("EPC value is return parser(tc) => %v, want %v", actual.VarGroups[i].EPC, normalTestExpect[index].VarGroups[i].EPC)
				}
				if actual.VarGroups[i].PDC != normalTestExpect[index].VarGroups[i].PDC {
					t.Errorf("PDC value is return parser(tc) => %v, want %v", actual.VarGroups[i].PDC, normalTestExpect[index].VarGroups[i].PDC)
				}
				for j := 0; j < int(normalTestExpect[index].VarGroups[i].PDC); j++ {
					if actual.VarGroups[i].EDT[j] != normalTestExpect[index].VarGroups[i].EDT[j] {
						t.Errorf("EDT value is return parser(tc) => %v, want %v", actual.VarGroups[i].EDT[j], normalTestExpect[index].VarGroups[i].EDT[j])
					}
				}
			}
		}
	}

	/*
		Test case
		case1: OPC error because less VarByteGroups(EPC/PDC/EDT)
		case2: OPC error because more VarByteGroups(EPC/PDC/EDT) => return not error
		case3: EDT error because less EDT
		case4: EDT error because more EDT => return not error
	*/
	exceptTestCase := [...]inputData{
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x03, 0x80, 0x01, 0x30, 0x80, 0x01, 0x31},
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x01, 0x80, 0x01, 0x30, 0x80, 0x01, 0x31},
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x01, 0x80, 0x02, 0x30},
		{0x10, 0x81, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x01, 0x30, 0x01, 0x60, 0x01, 0x80, 0x01, 0x30, 0x31},
	}

	exceptTestExpect := [...]FrameFormat{
		{
			EHD1: 0x10,
			EHD2: 0x81,
			TID:  0x0000,
			SEOJ: [3]uint8{0x05, 0xff, 0x01},
			DEOJ: [3]uint8{0x01, 0x30, 0x01},
			ESV:  0x60,
			OPC:  0x01,
			VarGroups: []VarByteGroup{
				{
					EPC: 0x80,
					PDC: 0x01,
					EDT: []uint8{0x30},
				},
			},
		},
	}

	for i, tc := range exceptTestCase {
		actual, err := parser(tc)
		if err == nil {
			if i == 1 || i == 3 {
				if actual.EHD1 != exceptTestExpect[0].EHD1 {
					t.Errorf("EHD1 value is return parser(tc) => %v, want %v", actual.EHD1, exceptTestExpect[0].EHD1)
				}
				if actual.EHD2 != exceptTestExpect[0].EHD2 {
					t.Errorf("EHD2 value is return parser(tc) => %v, want %v", actual.EHD2, exceptTestExpect[0].EHD2)
				}
				if actual.TID != exceptTestExpect[0].TID {
					t.Errorf("TID value is return parser(tc) => %v, want %v", actual.TID, exceptTestExpect[0].TID)
				}
				for i, v := range exceptTestExpect[0].SEOJ {
					if v != actual.SEOJ[i] {
						t.Errorf("SEOJ value is return parser(tc) => %v, want %v", v, exceptTestExpect[0].SEOJ[i])
					}
				}
				for i, v := range exceptTestExpect[0].DEOJ {
					if v != actual.DEOJ[i] {
						t.Errorf("DEOJ value is return parser(tc) => %v, want %v", v, exceptTestExpect[0].DEOJ[i])
					}
				}
				if actual.ESV != exceptTestExpect[0].ESV {
					t.Errorf("ESV value is return parser(tc) => %v, want %v", actual.ESV, exceptTestExpect[0].ESV)
				}
				if actual.OPC != exceptTestExpect[0].OPC {
					t.Errorf("OPC value is return parser(tc) => %v, want %v", actual.OPC, exceptTestExpect[0].OPC)
				}
				for i := 0; i < int(exceptTestExpect[0].OPC); i++ {
					if actual.VarGroups[i].EPC != exceptTestExpect[0].VarGroups[i].EPC {
						t.Errorf("EPC value is return parser(tc) => %v, want %v", actual.VarGroups[i].EPC, exceptTestExpect[0].VarGroups[i].EPC)
					}
					if actual.VarGroups[i].PDC != exceptTestExpect[0].VarGroups[i].PDC {
						t.Errorf("PDC value is return parser(tc) => %v, want %v", actual.VarGroups[i].PDC, exceptTestExpect[0].VarGroups[i].PDC)
					}
					for j := 0; j < int(exceptTestExpect[0].VarGroups[i].PDC); j++ {
						if actual.VarGroups[i].EDT[j] != exceptTestExpect[0].VarGroups[i].EDT[j] {
							t.Errorf("EDT value is return parser(tc) => %v, want %v", actual.VarGroups[i].EDT[j], exceptTestExpect[0].VarGroups[i].EDT[j])
						}
					}
				}
			} else {
				if i == 0 && !strings.Contains(err.Error(), "Failed to read EPC") {
					t.Fatalf("Response error message wrong. '%s' is expected to contain 'Failed to read EPC'", err.Error())
				}
				if i == 2 && !strings.Contains(err.Error(), "Failed to read EDT") {
					t.Fatalf("Response error message wrong. '%s' is expected to contain 'Failed to read EDT'", err.Error())
				}
			}
		}
	}
}
