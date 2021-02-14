package echonetlite

import (
	"fmt"
	"golang.org/x/xerrors"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// searchInstane get instance list from test device
// return Node has instances test device has
func (a *Auditor) searchInstane(dstIP net.IP, dstCode [3]uint8) (Node, int, error) {
	var node Node
	var index int
	exist := false
	for _, node = range a.DistNodes {
		if node.ip.String() == dstIP.String() {
			for i, inst := range node.Instances {
				if inst.ClassCode == dstCode {
					exist = true
					index = i
					break
				}
			}
		}
		if exist {
			break
		}
	}
	if !exist {
		return node, index, xerrors.Errorf("Invalid ClassCode")
	}

	return node, index, nil
}

// OpcFuzz send a number of ECHONET Lite packet whose EPCs is designated by argument "epc"
// and whose destnation object is designated by a.dst and dstCode.
// This function return 2 value, [2][]FrameFormat and error type.
// [0][i]FrameFormat means the packet sent and corresponds [1][i]FrameFormat that is recieve packet
func (a *Auditor) OpcFuzz(dstIP net.IP, dstCode [3]uint8) ([2][]FrameFormat, error) {
	fmt.Println("---Start OPC fuzzy---")
	var retFrames [2][]FrameFormat

	node, instIndex, exist := a.searchInstane(dstIP, dstCode)
	node.logger.Info("Start OPC fuzzy")
	if exist != nil {
		a.logger.Error("Invalid Class Code", zap.String("IPaddr", dstIP.String()), zap.String("CLASSCODE", fmt.Sprintf("0x%02X%02X%02X", dstCode[0], dstCode[1], dstCode[2])))
		return retFrames, xerrors.Errorf("Invalid Class Code")
	}

	inst := node.Instances[instIndex]

	payload := FrameFormat{
		EHD1: 0x10,
		EHD2: 0x81,
		SEOJ: nodeProfileEOJ,
		DEOJ: dstCode,
		ESV:  0x61,
		OPC:  0x00,
	}

	rand.Seed(time.Now().UnixNano())

	var sends []uint8
	for _, prop := range inst.Props {
		if prop.Set == "required" || prop.Set == "optional" {
			sends = append(sends, prop.EPC)
		}
	}
	if sends == nil {
		node.logger.Error("There are no SET property")
		return retFrames, xerrors.Errorf("Cannot OPC Fuzzy: There are no Property whose Set access rule")
	}
	// OPC [1:255]
	for i := 1; i < 256; i++ {
		var payloadData VarByteGroup
		var err error
		var propRand Property

		// choose property is generated random value
		randIndex := rand.Intn(len(sends))
		epc := sends[randIndex]
		for _, prop := range inst.Props {
			if prop.EPC == epc {
				propRand = prop
				break
			}
		}
		payloadData.EPC = epc

		// property data (EDT) generated random
		payloadData.EDT, err = RandProp(propRand)
		if err != nil {
			node.logger.Error("Generate random value Failed")
			return retFrames, xerrors.Errorf("Failed to generate random property: %w", err)
		}
		payloadData.PDC = uint8(len(payloadData.EDT))
		payload.OPC++
		payload.TID = uint16(rand.Intn(0xFFFF))
		payload.VarGroups = append(payload.VarGroups, payloadData)
		node.logger.Info("sent packet", zap.String("payload", fmt.Sprintf("%+v", payload)))
		retFrames[0] = append(retFrames[0], payload)
		err = SendEchonet(payload, node.connSend)
		if err != nil {
			node.logger.Error("Send packet Failed", zap.String("payload", fmt.Sprintf("%+v", payload)))
			return retFrames, xerrors.Errorf("Failed to send ECHONET Lite packet at OPC fuzzy: %w", err)
		}
		recv, err := node.RecvEchonet()
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				node.logger.Error("Receive packet Timeout", zap.String("payload", fmt.Sprintf("%+v", recv)))
			} else {
				node.logger.Error("Receive packet Failed", zap.String("payload", fmt.Sprintf("%+v", recv)), zap.String("message", err.Error()))
				return retFrames, xerrors.Errorf("Failed to recieve ECHONET Lite packet at OPC fuzzy: %w", err)
			}
		}
		node.logger.Info("received packet", zap.String("payload", fmt.Sprintf("%+v", recv)))
		retFrames[1] = append(retFrames[1], recv)
	}
	return retFrames, nil
}

// RandProp generate random value of Property Data(EDT).
// Designate Property by argument 'anlyzData'
// This function return 2 value, []uint8, error type.
// []uint8 is EDT randomly desided
func RandProp(anlyzData interface{}) ([]uint8, error) {
	var retNum []uint8

	rand.Seed(time.Now().UnixNano())

	if value, ok := anlyzData.([]interface{}); ok { // argument 'anlyzData' is []interface
		randIndex := rand.Intn(len(value))
		recNum, err := RandProp(value[randIndex])
		if err != nil {
			return retNum, err
		}
		for _, data := range recNum {
			retNum = append(retNum, data)
		}
		return retNum, nil

	} else if value, ok := anlyzData.(Property); ok { // argument 'anlyzData' is Property struct
		var anlyz interface{}
		if len(value.Data) > 1 {
			randIndex := rand.Intn(len(value.Data))
			anlyz = value.Data[randIndex]
		} else {
			anlyz = value.Data[0]
		}
		recNum, err := RandProp(anlyz)
		if err != nil {
			return recNum, xerrors.Errorf("Failed to generate rand EDT of CODE:0x%X: %w", value.EPC, err)
		}
		for _, num := range recNum {
			retNum = append(retNum, num)
		}
		return retNum, nil

	} else if value, ok := anlyzData.(Number); ok { // argument 'anlyzData' is Number struct
		if value.enum != nil {
			randNum := value.enum[rand.Int()%len(value.enum)]
			if strings.HasSuffix(value.format, "int8") {
				return []uint8{uint8(randNum)}, nil
			} else if strings.HasSuffix(value.format, "int16") {
				return []uint8{uint8(randNum >> 8), uint8(randNum) & 0xFF}, nil
			} else if strings.HasSuffix(value.format, "int32") {
				return []uint8{uint8(randNum >> 24), uint8(randNum>>16) & 0xFF, uint8(randNum>>8) & 0xFF, uint8(randNum) & 0xFF}, nil
			} else {
				return nil, xerrors.Errorf("Invalid format of Property")
			}

		} else if strings.HasPrefix(value.format, "uint") {
			max := uint(value.maximum)
			min := uint(value.minimum)
			randNum := uint(rand.Int()) % max
			if randNum < min {
				randNum = min
			}
			if strings.HasSuffix(value.format, "int8") {
				return []uint8{uint8(randNum)}, nil
			} else if strings.HasSuffix(value.format, "int16") {
				return []uint8{uint8(randNum >> 8), uint8(randNum) & 0xFF}, nil
			} else if strings.HasSuffix(value.format, "int32") {
				return []uint8{uint8(randNum >> 24), uint8(randNum>>16) & 0xFF, uint8(randNum>>8) & 0xFF, uint8(randNum) & 0xFF}, nil
			} else {
				return nil, xerrors.Errorf("Invalid format of Property")
			}
		} else {
			max := int(value.maximum)
			min := int(value.minimum)
			randNum := rand.Int()
			if randNum > max {
				randNum = max
			} else if randNum < min {
				randNum = min
			}
			if strings.HasSuffix(value.format, "int8") {
				return []uint8{uint8(randNum)}, nil
			} else if strings.HasSuffix(value.format, "int16") {
				return []uint8{uint8(randNum >> 8), uint8(randNum) & 0xFF}, nil
			} else if strings.HasSuffix(value.format, "int32") {
				return []uint8{uint8(randNum >> 24), uint8(randNum>>16) & 0xFF, uint8(randNum>>8) & 0xFF, uint8(randNum) & 0xFF}, nil
			} else {
				return nil, xerrors.Errorf("Invalid format of Property")
			}
		}
	} else if value, ok := anlyzData.(State); ok { // argument 'anlyzData' is State struct
		size := value.size
		randIndex := rand.Int() % len(value.enum)
		retEnum := value.enum[randIndex]
		retEdt := retEnum.edt
		if size == 0 {
			retNum = append(retNum, uint8(retEdt))
		} else {
			for i := size - 1; i >= 0; i-- {
				retNum = append(retNum, uint8(retEdt>>(i*8))&0xFF)
			}
		}
		return retNum, nil

	} else if value, ok := anlyzData.(Level); ok { // argument 'anlyzData' is Level struct
		size := int((len(value.base) - 2) / 2)
		if size < 1 {
			return nil, xerrors.Errorf("Invalid size")
		}
		base, err := strconv.ParseInt(value.base, 0, 64)
		if err != nil {
			return nil, xerrors.Errorf("Invalid format of number: %w", err)
		}
		randNum := base + int64(rand.Intn(int(value.maximum)))
		for i := size - 1; i >= 0; i-- {
			retNum = append(retNum, uint8(randNum>>(i*8))&0xFF)
		}
		return retNum, nil

	} else if value, ok := anlyzData.(Raw); ok { // argument 'anlyzData' is Raw struct
		var size int64
		if value.minSize == value.maxSize {
			size = value.maxSize
		} else {
			size = int64(rand.Intn(int(value.maxSize-value.minSize))) + value.minSize
		}
		for i := size - 1; i >= 0; i-- {
			randNum := uint8(rand.Intn(0xFF))
			retNum = append(retNum, uint8(randNum>>(i*4))&0xFF)
		}

		return retNum, nil

	} else if value, ok := anlyzData.(Object); ok { // argument 'anlyzData' is Object struct
		for _, data := range value.element {
			recNum, err := RandProp(data.data)
			if err != nil {
				return retNum, xerrors.Errorf("Failed to generate rand Object (NAME:%s): %w", data.name, err)
			}
			for _, num := range recNum {
				retNum = append(retNum, num)
			}
		}
		return retNum, nil

	} else if value, ok := anlyzData.(Array); ok { // argument 'anlyzData' is Array struct
		var items int64
		if value.maxItems == value.minItems {
			items = value.maxItems
		} else {
			items = int64(rand.Intn(int(value.maxItems-value.minItems))) + value.minItems
		}
		for i := 0; int64(i) < items; i++ {
			recNum, err := RandProp(value.data)
			if err != nil {
				return retNum, xerrors.Errorf("Failed to generate rand Array: %w", err)
			}
			for _, num := range recNum {
				retNum = append(retNum, num)
			}
		}
		return retNum, nil

	} else if value, ok := anlyzData.(Bitmap); ok { // argument 'anlyzData' is Bitmap struct
		var masked uint64
		var num uint64
		var index int64
		bitsize := 8
		masked = 0
		num = 0

		for _, el := range value.bitmaps {
			index = el.index
			recNum, err := RandProp(el.value)
			if err != nil {
				return retNum, xerrors.Errorf("Failed to generate rand Bitmap (Name:%s", el.name, err)
			}
			num = num | (uint64(recNum[len(recNum)-1]))
			// bitmask check
			cnt1 := 0
			cnt2 := 0
			to0 := false
			bitmask := el.bitmask
			for i := 0; i < bitsize; i++ {
				if bitmask%2 == 1 {
					for j := i; j < bitsize; j++ {
						bitmask = bitmask >> 1
						cnt2++
						if bitmask%2 == 0 {
							to0 = true
							break
						}
					}
				}
				if to0 {
					break
				}
				bitmask = bitmask >> 1
				cnt1++
			}
			// gen bitmask
			var mask uint64
			mask = 0
			for i := 0; i < cnt2; i++ {
				mask = mask | (1 << i)
			}

			masked = masked | ((mask<<cnt1)&(num<<cnt1))<<(index*8)
		}

		for i := value.size; i > 0; i-- {
			retNum = append(retNum, uint8((masked>>((i-1)*8))&0xFF))
		}

		return retNum, nil

	} else if value, ok := anlyzData.(NumericValues); ok { // argument 'anlyzData' is NumericValues struct
		randIndex := rand.Intn(len(value.enum))
		return []uint8{uint8(value.enum[randIndex].edt)}, nil

	} else if value, ok := anlyzData.(DateTime); ok { // argument 'anlyzData' is DateTime struct
		t := time.Now()
		year := t.Year()
		manth := int(t.Month())
		if value.size == 2 {
			return []uint8{uint8(manth), uint8(t.Day())}, nil
		} else if value.size == 3 {
			return []uint8{uint8(t.Hour()), uint8(t.Minute()), uint8(t.Second())}, nil
		} else if value.size == 4 {
			return []uint8{uint8((year >> 8) & 0xFF), uint8(year & 0xFF), uint8(manth), uint8(t.Day())}, nil
		} else if value.size == 6 {
			return []uint8{uint8((year >> 8) & 0xFF), uint8(year & 0xFF), uint8(manth), uint8(t.Day()), uint8(t.Hour()), uint8(t.Minute())}, nil
		} else if value.size == 7 {
			return []uint8{uint8((year >> 8) & 0xFF), uint8(year & 0xFF), uint8(manth), uint8(t.Day()), uint8(t.Hour()), uint8(t.Minute()), uint8(t.Second())}, nil
		} else {
			return nil, xerrors.Errorf("Invalid data of DateTime")
		}
	} else {
		return nil, xerrors.Errorf("Invalid data")
	}
}

// CheckValueValidetion desides whether property data is valid value.
// Property data (EDT), which you wanna check validetion, designated by argument 'rData'.
// This function return 2 value, bool and error.
// if bool is true, EDT and EPC are valid value.
func (node *Node) CheckValueValidetion(inst Instance, rData VarByteGroup) (bool, error) {
	var prop Property
	epcExist := false
	for _, prop = range inst.Props {
		if prop.EPC == rData.EPC {
			epcExist = true
			break
		}
	}
	if !epcExist {
		node.logger.Error("Invalid EPC", zap.String("EPC", fmt.Sprintf("0x%02X", rData.EPC)))
		return false, xerrors.Errorf("Invalid EPC")
	}
	for _, edtData := range prop.Data {
		rslt, err := elementCorrectRange(edtData, rData.EDT)
		if err != nil {
			node.logger.Error("Out of range", zap.String("EPC", fmt.Sprintf("0x%02X", rData.EPC)))
			return false, xerrors.Errorf("Failed to check data whose range is correct: %w", err)
		} else if rslt {
			return true, nil
		}
	}
	return false, nil
}

// elementCorrectRange desides whether EDT is valid value.
func elementCorrectRange(varType interface{}, edt []uint8) (bool, error) {
	if value, ok := varType.([]interface{}); ok { // varType is []interface
		for _, checkee := range value {
			rslt, err := elementCorrectRange(checkee, edt)
			if err != nil {
				return rslt, err
			}
			if rslt {
				return true, nil
			}
		}
		return false, nil

	} else if value, ok := varType.(Number); ok { // varType is Number struct
		if value.enum != nil {
			var anlyzData int64
			for i, data := range edt {
				anlyzData = anlyzData | int64((int8(data) << ((len(edt) - i - 1) * 8)))
			}

			for _, enum := range value.enum {
				if enum == anlyzData {
					return true, nil
				}
			}
			return false, nil
		} else if strings.HasPrefix(value.format, "uint") {
			var anlyzData uint64
			anlyzData = 0
			for i := 0; i < len(edt); i++ {
				anlyzData = anlyzData + (uint64(edt[i]) * uint64(math.Pow(0x100, float64(len(edt)-1-i))))
			}
			if anlyzData <= uint64(value.maximum) && anlyzData >= uint64(value.minimum) {
				return true, nil
			} else {
				return false, nil
			}
		} else {
			var anlyzData int64
			for i, data := range edt {
				anlyzData = anlyzData | int64((int8(data) << ((len(edt) - i - 1) * 8)))
			}
			if anlyzData <= int64(value.maximum) && anlyzData >= int64(value.minimum) {
				return true, nil
			} else {
				return false, nil
			}
		}

	} else if value, ok := varType.(State); ok { // varType is State struct
		var anlyzData int64
		if int64(len(edt)) != value.size {
			return false, nil
		}
		anlyzData = 0
		for i := 0; i < len(edt); i++ {
			anlyzData = anlyzData | (int64(edt[i]) * int64(math.Pow(0x100, float64(len(edt)-1-i))))
		}
		for _, enum := range value.enum {
			if anlyzData == enum.edt {
				return true, nil
			}
		}
		return false, nil

	} else if value, ok := varType.(Level); ok { // varType is Level struct
		var anlyzData uint64
		anlyzData = 0
		for i := 0; i < len(edt); i++ {
			anlyzData = anlyzData + (uint64(edt[i]) * uint64(math.Pow(0x100, float64(len(edt)-1-i))))
		}
		base, _ := strconv.ParseUint(value.base, 0, 64)

		if anlyzData <= base+value.maximum && anlyzData >= base {
			return true, nil
		}
		return false, nil
	} else if value, ok := varType.(Raw); ok { // varType is Raw struct
		length := int64(len(edt))
		if length <= value.maxSize && length >= value.minSize {
			return true, nil
		}
		return false, nil
	} else if value, ok := varType.(Object); ok { // varType is Object struct
		var beforeIndex uint64
		beforeIndex = 0
		for _, data := range value.element {
			rslt := false
			for _, elData := range data.data {
				var sizeOfData uint64
				sizeOfData, err := getDataSize(elData)
				if err != nil {
					if strings.Contains(err.Error(), "Array") || strings.Contains(err.Error(), "Raw") {
						if sizeOfData == 0 {
							rslt = true
							break
						}
						sizeOfData = uint64(len(edt)) - beforeIndex - 1
						check, err := elementCorrectRange(elData, edt[beforeIndex:beforeIndex+sizeOfData])
						if err != nil {
							return false, err
						} else if check {
							rslt = true
							beforeIndex += sizeOfData
							break
						}
					} else {
						return false, xerrors.Errorf("Failed to check range or Object: %w", err)
					}
				} else {
					check, err := elementCorrectRange(elData, edt[beforeIndex:beforeIndex+sizeOfData])
					if err != nil {
						return false, err
					} else if check {
						rslt = true
						beforeIndex += sizeOfData
						break
					}
				}
			}
			if !rslt {
				return false, nil
			}
		}
		return true, nil

	} else if value, ok := varType.(Array); ok { // varType is Array struct
		lenItems := len(edt) / int(value.itemSize)
		for i := 0; i < lenItems; i += int(value.itemSize) {
			item := edt[i*int(value.itemSize) : i*int(value.itemSize)+int(value.itemSize)]
			rslt, err := elementCorrectRange(value.data, item)
			if err != nil {
				return false, xerrors.Errorf("Array type Property cannot check value is valid: %w", err)
			}
			if !rslt {
				return false, nil
			}
		}
		return true, nil

	} else if value, ok := varType.(NumericValues); ok { // varType is NumericValue struct
		var anlyzData int64
		anlyzData = 0
		if int64(len(edt)) != value.size {
			return false, nil
		}
		for i := 0; int64(i) < value.size; i++ {
			anlyzData = anlyzData | (int64(edt[i]) << (i * 8))
		}
		for _, enum := range value.enum {
			if anlyzData == enum.edt {
				return true, nil
			}
		}
		return false, nil

	} else if value, ok := varType.(Bitmap); ok { // varType is Bitmap struct
		var anlyzData int64
		anlyzData = 0
		if int64(len(edt)) != value.size {
			return false, nil
		}
		for i := 0; i < len(edt); i++ {
			anlyzData = anlyzData | (int64(edt[i]) * int64(math.Pow(0x100, float64(len(edt)-1-i))))
		}

		bitmask, _ := genBitmask(value)
		bitmask = bitmask ^ 0xFFFFFFFF
		if bitmask&uint64(anlyzData) != 0 {
			return false, nil
		} else {
			return true, nil
		}

	} else if value, ok := varType.(DateTime); ok { // varType is DataTime struct
		var manth, day int
		if value.size == 4 || value.size == 6 || value.size == 7 {
			manth = 2
			day = 3
			if value.size != 4 {
				if edt[4] > 23 || edt[4] < 0 || edt[5] > 59 || edt[5] < 0 {
					return false, nil
				} else if value.size == 7 {
					if edt[6] > 59 || edt[6] < 0 {
						return false, nil
					}
				}
			}
		} else if value.size == 2 {
			manth = 0
			day = 1
		} else if value.size == 3 {
			if edt[0] > 23 || edt[0] < 0 || edt[1] > 59 || edt[1] < 0 || edt[2] > 59 || edt[2] < 0 {
				return false, nil
			}
			return true, nil
		} else {
			return false, xerrors.Errorf("Invalid size of data")
		}
		t := time.Date(2020, time.Month(edt[manth]), int(edt[day]), 00, 00, 00, 123456, time.UTC)
		if t.Month() != time.Month(edt[manth]) || edt[manth] > 12 || int(edt[day]) > 31 {
			return false, nil
		}

		return true, nil
	}

	return false, xerrors.Errorf("Invalid Type of data")
}

// return varType's length
func getDataSize(varType interface{}) (uint64, error) {
	if value, ok := varType.(Number); ok {
		if strings.HasSuffix(value.format, "int8") {
			return 1, nil
		} else if strings.HasSuffix(value.format, "int16") {
			return 2, nil
		} else if strings.HasSuffix(value.format, "int32") {
			return 4, nil
		} else if strings.HasSuffix(value.format, "int64") {
			return 8, nil
		}

	} else if value, ok := varType.(State); ok {
		if value.size == 0 {
			return 1, nil
		}
		return uint64(value.size), nil

	} else if value, ok := varType.(Level); ok {
		return uint64((len(value.base) - 2) / 2), nil

	} else if value, ok := varType.(Raw); ok {
		if value.maxSize == value.minSize {
			return uint64(value.minSize), nil
		}
		return 0, xerrors.Errorf("Raw")

	} else if value, ok := varType.(Bitmap); ok {
		return uint64(value.size), nil

	} else if value, ok := varType.(NumericValues); ok {
		if value.size == 0 {
			return 1, nil
		}
		return uint64(value.size), nil

	} else if value, ok := varType.(DateTime); ok {
		return uint64(value.size), nil

	} else if value, ok := varType.(Object); ok {
		var retNum uint64
		retNum = 0
		for _, data := range value.element {
			num, err := getDataSize(data.data[0])
			if err != nil {
				return 0, err
			}
			retNum += num
		}
		return retNum, nil

	} else if value, ok := varType.(Array); ok {
		if value.maxItems == value.minItems {
			return uint64(value.itemSize * value.maxItems), nil
		}
		return 0, xerrors.Errorf("Array")

	}
	return 0, xerrors.Errorf("Invalid Type of data")
}

// Generate bitmap's bitmask
func genBitmask(bitmap Bitmap) (uint64, error) {
	var retMask uint64
	var index int64
	var mask uint64
	bitsize := 8
	retMask = 0
	for _, el := range bitmap.bitmaps {
		index = el.index
		// bitmask check
		// cnt1 counts number of 0
		// cnt2 counts number of 1
		cnt1 := 0
		cnt2 := 0
		to0 := false
		bitmask := el.bitmask
		for i := 0; i < bitsize; i++ {
			if bitmask%2 == 1 {
				for j := i; j < bitsize; j++ {
					bitmask = bitmask >> 1
					cnt2++
					if bitmask%2 == 0 {
						to0 = true
						break
					}
				}
			}
			if to0 {
				break
			}
			bitmask = bitmask >> 1
			cnt1++
		}
		// gen bitmask
		mask = 0
		for i := 0; i < cnt2; i++ {
			mask = mask | (1 << i)
		}
		retMask = retMask | mask<<cnt1<<(index*8)

	}
	return retMask, nil
}

// CheckFlowValidation check whether communication flow is valid.
// If flow is invalid, output ERROR log.
func (node *Node) CheckFlowValidation(sent FrameFormat, recv FrameFormat) error {
	var retError error
	retError = node.CheckEpcExist(sent, recv)
	errormes := xerrors.Errorf("Invalid Flow: ")
	if sent.TID != recv.TID {
		node.logger.Error(fmt.Sprintf("%sNot Correspond: Transaction ID", errormes))

	} else if sent.ESV&0x0F != recv.ESV&0x0F && recv.ESV != 0x74 {
		node.logger.Error(fmt.Sprintf("%sNot Correspond: ESV", errormes))

	} else if sent.SEOJ != recv.DEOJ || sent.DEOJ != recv.SEOJ {
		node.logger.Error(fmt.Sprintf("%sNot Correspond: EOJ", errormes))

	} else if (recv.OPC != uint8(len(recv.VarGroups)) && sent.ESV != 0x6E) || (recv.OPC-recv.OPCG != uint8(len(recv.VarGroups)) && sent.ESV == 0x6E) {
		node.logger.Error(fmt.Sprintf("%sOPC and length of Property data do not match", errormes))

	} else if recv.ESV&0xF0 != 0x50 && recv.ESV&0xF0 != 0x70 {
		node.logger.Error(fmt.Sprintf("%sInvalid ESV 0x%02X", errormes, recv.ESV))

	} else if sent.OPC < recv.OPC {
		node.logger.Error(fmt.Sprintf("%srecieve packet OPC is too large", errormes))

	} else if recv.OPC&0xF0 == 0x70 && recv.OPC != sent.OPC {
		node.logger.Error(fmt.Sprintf("%srecieve packet OPC is too small", errormes))

	} else if retError != nil {
		node.logger.Error(fmt.Sprintf("%sInvalid EPC: %s", errormes, retError))

	} else if recv.ESV == 0x71 || recv.ESV == 0x7E {
		for _, prop := range recv.VarGroups {
			if prop.PDC != 0x00 || len(prop.EDT) > 0 {
				node.logger.Error(fmt.Sprintf("%sEDT field has data", errormes))
			}
		}
	} else if recv.ESV == 0x72 {
		for _, prop := range recv.VarGroups {
			if prop.PDC == 0x00 || len(prop.EDT) == 0 {
				node.logger.Error(fmt.Sprintf("%sEDT field has data", errormes))
			}
		}
	}
	if sent.ESV == 0x6E {
		sentE := sent
		recvE := recv
		sentE.ESV = 0x62
		sentE.OPC = sent.OPCG
		sentE.VarGroups = sent.VarGroupsG
		recvE.ESV = 0x72
		recvE.OPC = recv.OPCG
		recvE.VarGroups = recv.VarGroupsG
		err := node.CheckFlowValidation(sentE, recvE)
		if err != nil {
			return err
		}
	}
	return nil
}

// CheckEpcExist check whether sent.EPC or recv.EPC is only one.
// If so, output ERROR log.
func (node *Node) CheckEpcExist(sent FrameFormat, recv FrameFormat) error {
	// Check property which sent packet has is not in receive packet
	// dataR is receive packet's data
	// dataS is sent packet's data
	for _, dataR := range recv.VarGroups {
		exist := false
		for _, dataS := range sent.VarGroups {
			if dataR.EPC == dataS.EPC {
				exist = true
				break
			}
		}
		if !exist {
			node.logger.Error(fmt.Sprintf("There are strange EPC:%02X in receive packet", dataR))
		}
	}
	// Check property which sent packet has is not in receive packet
	for _, dataS := range sent.VarGroups {
		exist := false
		for _, dataR := range recv.VarGroups {
			if dataR.EPC == dataS.EPC {
				exist = true
				break
			}
		}
		if !exist {
			node.logger.Error(fmt.Sprintf("There are no EPC:%02X in receive packet", dataS))
		}
	}

	if sent.ESV == 0x6E {
		for _, dataR := range recv.VarGroupsG {
			exist := false
			for _, dataS := range sent.VarGroupsG {
				if dataR.EPC == dataS.EPC {
					exist = true
					break
				}
			}
			if !exist {
				node.logger.Error(fmt.Sprintf("There are strange EPC:%02X in receive packet", dataR))
			}
		}
		// Check property which sent packet has is not in receive packet
		for _, dataS := range sent.VarGroupsG {
			exist := false
			for _, dataR := range recv.VarGroupsG {
				if dataR.EPC == dataS.EPC {
					exist = true
					break
				}
			}
			if !exist {
				node.logger.Error(fmt.Sprintf("There are no EPC:%02X in receive packet", dataS))
			}
		}
	}
	return nil
}

// Check check communicatoin flow, epc and data value
// if invalid, output ERROR log
func (node *Node) Check(sent *FrameFormat, recv *FrameFormat) error {
	var inst Instance
	exist := false
	for _, inst = range node.Instances {
		if sent.DEOJ == inst.ClassCode {
			exist = true
			break
		}
	}
	if !exist {
		node.logger.Error("Instance Code incorresponded")
		return xerrors.Errorf("There are no instance (CODE:%02X%02X%02X)", sent.DEOJ[0], sent.DEOJ[1], sent.DEOJ[2])
	}
	if recv.EHD1 == 0 {
		node.logger.Error("Couldn't receive packet", zap.String("SentPacket", fmt.Sprintf("%+v", sent)))
		return xerrors.Errorf("Receive packet is NULL")
	}
	node.CheckEpcExist(*sent, *recv)
	node.CheckFlowValidation(*sent, *recv)
	for _, inst := range node.Instances {
		if inst.ClassCode == recv.SEOJ {
			for _, varGroup := range recv.VarGroups {
				node.CheckValueValidetion(inst, varGroup)
			}
			break
		}
	}
	return nil
}

//func (inst *Instance) GetProperties() ([]Property, []Property, []Property) {
//	var GetProps, SetProps, InfProps []Property
//	for _, prop := range inst.Props {
//		if prop.ImplementGet == true {
//			GetProps = append(GetProps, prop)
//		}
//		if prop.ImplementSet == true {
//			SetProps = append(SetProps, prop)
//		}
//		if prop.ImplementInf == true {
//			InfProps = append(InfProps, prop)
//		}
//	}
//	return GetProps, SetProps, InfProps
//}
//
//func (inst *Instance) GeneratePropMap(mapType string) ([]uint8, error) {
//	var props []Property
//	var retEDT []uint8
//	var propMapBool [16][8]bool
//	if strings.Contains(mapType, "Get") {
//		props, _, _ = inst.GetProperties()
//	} else if strings.Contains(mapType, "Set") {
//		props, _, _ = inst.GetProperties()
//	} else if strings.Contains(mapType, "Inf") {
//		props, _, _ = inst.GetProperties()
//	} else {
//		return nil, xerrors.Errorf("Invalid property map type")
//	}
//
//	if len(props) < 16 {
//		retEDT = append(retEDT, uint8(len(props)))
//		for _, prop := range props {
//			retEDT = append(retEDT, prop.EPC)
//		}
//	} else {
//		retEDT = append(retEDT, uint8(len(props)))
//
//		var propMapString string
//
//		for _, prop := range props {
//			propMapBool[prop.EPC%16][(prop.EPC>>4)-8] = true
//		}
//		for i := 0; i < 16; i++ {
//			for j := 0; j < 16; j++ {
//				if propMapBool[i][7-1] {
//					propMapString = propMapString + "1"
//				} else {
//					propMapString = propMapString + "0"
//				}
//			}
//		}
//		propMapInt64, err := strconv.ParseInt(propMapString, 2, 64)
//		if err != nil {
//			return nil, xerrors.Errorf("property map generate refused: %w", err)
//		}
//
//		for i := 7; i >=0; i-- {
//			retEDT = append(retEDT, uint8(propMapInt64>>(8*i))&0xFF)
//		}
//	}
//	return retEDT, nil
//}
//
//func (node *Node) Impostor(classCode [3]uint8) error {
//	connMulti, err := net.Dial("udp4", "224.0.23.0:3610")
//	if err != nil {
//		node.logger.Error("Multicast connection refused")
//	}
//
//	payload := FrameFormat{
//		EHD1: 0x10,
//		EHD2: 0x81,
//		SEOJ: nodeProfileEOJ,
//		DEOJ: nodeProfileEOJ,
//		ESV:  0x73,
//		OPC:  0x01,
//		VarGroups: []VarByteGroup{
//			{
//				EPC: 0xD5,
//				PDC: 0x00,
//				EDT: nil,
//			},
//		},
//	}
//	return nil
//}

// TODO 使われてない
func edtFuzz(anlyzData interface{}) ([]uint8, error) {
	var retNum []uint8

	rand.Seed(time.Now().UnixNano())

	if value, ok := anlyzData.([]interface{}); ok { // argument 'anlyzData' is []interface
		randIndex := rand.Intn(len(value))
		recNum, err := edtFuzz(value[randIndex])
		if err != nil {
			return retNum, err
		}
		for _, data := range recNum {
			retNum = append(retNum, data)
		}
		return retNum, nil

	} else if value, ok := anlyzData.(Number); ok { // argument 'anlyzData' is Number struct
		if value.enum != nil {
			var outNum int64
			for random := true; random; {
				outNum = int64(rand.Int() & 0xFFFFFFFF)
				for _, enum := range value.enum {
					if outNum == enum {
						random = false
						break
					}
				}
				if !random {
					random = true
				} else {
					random = false
				}
			}
			if strings.HasSuffix(value.format, "int8") {
				return []uint8{uint8(outNum)}, nil
			} else if strings.HasSuffix(value.format, "int16") {
				return []uint8{uint8(outNum >> 8), uint8(outNum) & 0xFF}, nil
			} else if strings.HasSuffix(value.format, "int32") {
				return []uint8{uint8(outNum >> 24), uint8(outNum>>16) & 0xFF, uint8(outNum>>8) & 0xFF, uint8(outNum) & 0xFF}, nil
			} else {
				return nil, xerrors.Errorf("Invalid format of Property")
			}
		} else if strings.HasPrefix(value.format, "uint") {
			max := uint(value.maximum)
			outNum := max + 1
			if strings.HasSuffix(value.format, "int8") {
				return []uint8{uint8(outNum)}, nil
			} else if strings.HasSuffix(value.format, "int16") {
				return []uint8{uint8(outNum >> 8), uint8(outNum) & 0xFF}, nil
			} else if strings.HasSuffix(value.format, "int32") {
				return []uint8{uint8(outNum >> 24), uint8(outNum>>16) & 0xFF, uint8(outNum>>8) & 0xFF, uint8(outNum) & 0xFF}, nil
			} else {
				return nil, xerrors.Errorf("Invalid format of Property")
			}
		} else {
			max := int(value.maximum)
			min := int(value.minimum)
			var outNum int
			if outNum > max {
				outNum = max
			} else if outNum < min {
				outNum = min
			}
			if strings.HasSuffix(value.format, "int8") {
				return []uint8{uint8(outNum)}, nil
			} else if strings.HasSuffix(value.format, "int16") {
				return []uint8{uint8(outNum >> 8), uint8(outNum) & 0xFF}, nil
			} else if strings.HasSuffix(value.format, "int32") {
				return []uint8{uint8(outNum >> 24), uint8(outNum>>16) & 0xFF, uint8(outNum>>8) & 0xFF, uint8(outNum) & 0xFF}, nil
			} else {
				return nil, xerrors.Errorf("Invalid format of Property")
			}
		}
	} else if value, ok := anlyzData.(State); ok { // argument 'anlyzData' is State struct
		var outNum int64
		size := value.size
		for random := true; random; {
			outNum = int64(rand.Int() & 0xFFFFFFFF)
			for _, enum := range value.enum {
				if outNum == enum.edt {
					random = false
					break
				}
			}
			if !random {
				random = true
			} else {
				random = false
			}
		}
		if size == 0 {
			retNum = append(retNum, uint8(outNum))
		} else {
			for i := size - 1; i >= 0; i-- {
				retNum = append(retNum, uint8(outNum>>(i*4))&0xFF)
			}
		}
		return retNum, nil
	}
	return nil, nil
}

func (a *Auditor) Fuzz(dstIP net.IP, dstCode [3]uint8) error {
	fmt.Println("---Start Fuzzing---")
	var payload FrameFormat
	var node Node
	var inst Instance
	var err error
	rand.Seed(time.Now().UnixNano())

	node, instIndex, err := a.searchInstane(dstIP, dstCode)
	if err != nil {
		return err
	}
	inst = node.Instances[instIndex]

	payload.EHD1 = 0x10
	payload.EHD2 = 0x81
	payload.TID = uint16(rand.Int() & 0xFFFF)
	payload.SEOJ = nodeProfileEOJ
	payload.DEOJ = inst.ClassCode

	// ESV Fuzzing
	// TODO 判定どうする
	//payload.ESV = 0x01
	//payload.OPC = 0x01
	//payload.VarGroups =[]VarByteGroup{
	//		{
	//		EPC: 0x80,
	//		PDC: 0x01,
	//		EDT: []uint8{0x30},
	//	},
	//}

	// EPC Fuzzing
	esvs := []uint8{0x60, 0x61, 0x62}
	for _, esv := range esvs {
		payload.ESV = esv
		payload.OPC = 0x01
		payload.VarGroups = []VarByteGroup{
			{
				PDC: 0x01,
			},
		}
		for random := true; random; {
			payload.VarGroups[0].EPC = uint8(rand.Int() & 0xFF)
			for _, epc := range inst.Props {
				if payload.VarGroups[0].EPC == epc.EPC {
					random = false
				}
			}
			if !random {
				random = true
			} else {
				random = false
			}
		}

		for _, prop := range inst.Props {
			if prop.EPC == payload.VarGroups[0].EPC {
				payload.VarGroups[0].EDT, err = RandProp(prop.Data)
				if err != nil {
					return xerrors.Errorf("Failed to generate Rand Data (EDT:0x%02X): %w", payload.VarGroups[0].EPC, err)
				}
			}
		}

		err := SendEchonet(payload, node.connSend)
		if err != nil {
			return xerrors.Errorf("Failed to send ECHONET Lite packet at Fuzzy: %w", err)
		}
		recv, err := node.RecvEchonet()
		if err != nil {
			return xerrors.Errorf("Failed to recieve ECHONET Lite packet at Fuzzy: %w", err)
		}
		err = node.CheckFlowValidation(payload, recv)
		if err != nil {
			// TODO Not Error FlowInvalid
		}
		if recv.ESV&0xF0 != 0x50 {
			// TODO Not Error ESVInvalid
		}
	}

	//// OPC Fuzz
	//for _, esv := range esvs {
	//	var datas []VarByteGroup
	//	datas = make([]VarByteGroup, 2, 2)
	//	for i := 0; i < 2; i++ {
	//		propIndex := rand.Int() % len(inst.Props)
	//		datas[i].EPC = inst.Props[propIndex].EPC
	//		datas[i].EDT, err = RandProp(inst.Props[propIndex])
	//		if err != nil {
	//			return xerrors.Errorf("Failed to generate Rand Data (EDT:0x%02X): %w", datas[i].EPC, err)
	//		}
	//		datas[i].PDC = uint8(len(datas[i].EDT))
	//	}
	//	payload.ESV = esv
	//	payload.VarGroups = datas
	//	// TODO 判定どうしよう
	//	// OPC - 1
	//	payload.OPC = 0x01
	//	err = SendEchonet(payload, a.connSend)
	//	if err != nil {
	//		return xerrors.Errorf("Failed to send ECHONET Lite packet at Fuzzy: %w", err)
	//	}
	//	recv, err := RecvEchonet(a.connSend)
	//	if err != nil {
	//		return xerrors.Errorf("Failed to recieve ECHONET Lite packet at Fuzzy: %w", err)
	//	}
	//	err = CheckFlowValidation(payload, recv)
	//	if err != nil {
	//		// TODO Not Error FlowInvalid
	//	}
	//	// OPC + 1
	//	payload.OPC = 0x03
	//	err = SendEchonet(payload, a.connSend)
	//	if err != nil {
	//		return xerrors.Errorf("Failed to send ECHONET Lite packet at Fuzzy: %w", err)
	//	}
	//	recv, err = RecvEchonet(a.connSend)
	//	if err != nil {
	//		return xerrors.Errorf("Failed to recieve ECHONET Lite packet at Fuzzy: %w", err)
	//	}
	//	err = CheckFlowValidation(payload, recv)
	//	if err != nil {
	//		// TODO Not Error FlowInvalid
	//	}
	//}
	// PDC Fuzz TODO どうしよう
	// EDT Fuzz TODO どうしよう
	for _, esv := range esvs {
		var data []VarByteGroup
		data = make([]VarByteGroup, 1, 1)
		payload.ESV = esv
		data[0].EPC = 0x80
		data[0].PDC = 0x01
		data[0].EDT = []uint8{0x11}
		payload.VarGroups = data
		err := SendEchonet(payload, node.connSend)
		if err != nil {
			return xerrors.Errorf("Failed to send ECHONET Lite packet at Fuzzy: %w", err)
		}
		recv, err := node.RecvEchonet()
		if err != nil {
			return xerrors.Errorf("Failed to recieve ECHONET Lite packet at Fuzzy: %w", err)
		}
		err = node.CheckFlowValidation(payload, recv)
		if err != nil {
			// TODO Not Error FlowInvalid
		}
		if recv.ESV&0xF0 != 0x50 {
			// TODO Not Error ESVInvalid
		}
	}
	return nil
}
