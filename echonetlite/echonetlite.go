package echonetlite

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	"github.com/c-bata/go-prompt"
	"github.com/tttfrfr2/ECHONETTester/util"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

var sc = bufio.NewScanner(os.Stdin)

func nextLine() string {
	sc.Scan()
	return sc.Text()
}

// Print all IP address of Nodes
func chooseNode(a *Auditor) *Node {
	fmt.Printf("(ECHONET Lite:Information)> Node addresses are...\n")
	fmt.Printf("   -------------- IP address --------------\n")
	for i, node := range a.DistNodes {
		fmt.Printf("   > index[%d]    IP address:%s\n", i+1, node.ip.String())
	}
	fmt.Printf("   ----------------------------------------\n")
	fmt.Printf("(ECHONET Lite:Information)> If choose node IP address %s, input '1'\n", a.DistNodes[0].ip.String())
	fmt.Printf("(ECHONET Lite:Information)> if you wanna EXIT, input '0'\n")
	fmt.Printf("(Input)> ")
	index, err := strconv.ParseInt(nextLine(), 10, 64)
	if err != nil || index > int64(len(a.DistNodes)) {
		fmt.Printf("(ECHONET Lite:Error) > Input Error\n")
		a.logger.Error("Input Index Error")
		return nil
	} else if index == 0 {
		return nil
	}
	return &a.DistNodes[index-1]
}

func (a *Auditor) executorEchonet(in string) {
	if in == "" {
	} else if in == "OPC Fuzz" {
		var node *Node
		var Frames [2][]FrameFormat
		var err error

		node = chooseNode(a)

		if node == nil {
			return
		}
		for _, inst := range node.Instances {
			node.logger.Info("Start to OPC fuzzing", zap.String("instance", inst.ClassName))
			Frames, err = a.OpcFuzz(node.ip, inst.ClassCode)
			if err != nil {
				return
			}
			node.logger.Info("Finished to OPC fuzzing", zap.String("instance", inst.ClassName))
		}
		node.logger.Info("Start to Check receive packet", zap.String("IPaddr", fmt.Sprintf("%s", node.ip.String())))
		for i := 0; i < len(Frames[0]); i++ {
			node.Check(&Frames[0][i], &Frames[1][i])
		}
		node.logger.Info("Finished Check receive packet")
	} else if in == "Communicate" {
		var node *Node
		node = chooseNode(a)
		if node == nil {
			return
		}
		err := node.Communicate()
		if err != nil {
			fmt.Printf("(ECHONET Lite:Error) > %s\n", err)
			node.logger.Error("Communication Failed", zap.String("message", fmt.Sprintf("%s", err)))
		}
		node.logger.Info("Finished to communicate", zap.String("IPaddr", node.ip.String()))
	} else if in == "exit" {
		fmt.Println("Exit tool")
		os.Exit(0)
		return
	} else {
		fmt.Println("Command not found")
	}
}

func (a *Auditor) completerEchonet(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "OPC Fuzz", Description: "Fuzzing with OPC [0:255] against Target IoT device"},
		{Text: "Communicate", Description: "Communicate with IoT device"},
		{Text: "exit", Description: "Exit tool"},
		//{Text: "", Description: ""},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func (a *Auditor) AddDistNodes(dsts []net.IP) error {
	// receive connection config
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP("localhost"),
		Port: 3610,
	}
	connectionReciveECHONET, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		a.logger.Error("Create Receive UDP Sokcet Failed", zap.String("IPaddr", udpAddr.IP.String()), zap.String("Port", fmt.Sprintf("%d", udpAddr.Port)), zap.String("message", fmt.Sprintf("%s", err)))
	}
	for _, dst := range dsts {
		var node Node

		dirNodeLog, fileNodeLog := filepath.Split("echonet/" + TimeStr + "-" + dst.String() + ".log")
		node.logger = util.InitLogger(dirNodeLog + fileNodeLog)
		if node.logger == nil {
			return xerrors.Errorf("Create logger failed")
		}
		node.ip = dst
		nodeProfileEOJ = [3]uint8{0x0E, 0xF0, 0x01}
		node.connRecv = connectionReciveECHONET

		connectionSendECHONET, err := net.Dial("udp4", fmt.Sprintf("%s:3610", dst.String()))
		if err != nil {
			a.logger.Error("Create Send Connection Failed", zap.String("IPaddr", dst.String()))
			return xerrors.Errorf("Couldn't connect to target device %w", err)
		}
		node.connSend = connectionSendECHONET

		// Get Instance list of node
		payload := FrameFormat{
			EHD1: 0x10,
			EHD2: 0x81,
			SEOJ: nodeProfileEOJ,
			DEOJ: nodeProfileEOJ,
			ESV:  0x62,
			OPC:  0x01,
			VarGroups: []VarByteGroup{
				{
					EPC: 0xD6,
					PDC: 0x00,
					EDT: nil,
				},
			},
		}
		go func() {
			err := SendEchonet(payload, node.connSend)
			if err != nil {
				payload.DEOJ = [3]uint8{0x0E, 0xF0, 0x02}
				err = SendEchonet(payload, node.connSend)
				if err != nil {
					a.logger.Error("Sent packet failed")
				}
			}
		}()
		recv, err := node.RecvEchonet()
		if err != nil {
			a.logger.Error("Couldn't receive packet from Node Profile Object", zap.String("IPaddr", node.ip.String()))
			continue
		} else if recv.ESV&0x70 != 0x70 {
			a.logger.Error("Invalid data flow", zap.String("IPaddr", node.ip.String()))
			continue
		}

		// instList: list of instance CODE
		instList := make([][3]uint8, int(recv.VarGroups[0].EDT[0])+1, int(recv.VarGroups[0].EDT[0])+1)
		instList[0] = payload.DEOJ
		for i := 0; i < int(recv.VarGroups[0].EDT[0]); i++ {
			index := (i * 3) + 1
			instList[i+1][0] = recv.VarGroups[0].EDT[index]
			instList[i+1][1] = recv.VarGroups[0].EDT[index+1]
			instList[i+1][2] = recv.VarGroups[0].EDT[index+2]
		}

		// ECHONET Lite specification version
		fmt.Printf("(ECHONET Lite:Information)> Input ECHONET Lite Version that test device use ('A' ~ 'M')\n")
		fmt.Printf("(Input)> ")
		release := nextLine()

		// Cleate instance
		dirJson, fileJson := filepath.Split("echonetlite/class.json")
		json, err := ioutil.ReadFile(dirJson + fileJson)
		if err != nil {
			return xerrors.Errorf(fmt.Sprintf("There are not %s", dirJson+fileJson))
		}
		for _, instCODE := range instList {
			instance, err := node.CreateObject(instCODE, release, json)
			if err != nil {
				a.logger.Error("Create Object Error", zap.String("CLASS", fmt.Sprintf("%02X%02X%02X", instCODE[0], instCODE[1], instCODE[2])))
				return xerrors.Errorf("Failed to Create Object (CLASSCODE:%+v):%w", instCODE, err)
			}
			// Set property map create
			setPropMap, err := node.GetPropMap(instCODE, 0x9E)
			if err != nil {
				a.logger.Error("Get Set property map Failed", zap.String("CLASS", fmt.Sprintf("%02X%02X%02X", instCODE[0], instCODE[1], instCODE[2])))
				return xerrors.Errorf("Failed to get Set property map (CLASSCODE:%+v): %w", instCODE, err)
			}
			for _, setProp := range setPropMap {
				for i := 0; i < len(instance.Props); i++ {
					if setProp == instance.Props[i].EPC {
						instance.Props[i].ImplementSet = true
					}
				}
			}

			// Get property map create
			getPropMap, err := node.GetPropMap(instCODE, 0x9F)
			if err != nil {
				a.logger.Error("Get Get property map Failed", zap.String("CLASS", fmt.Sprintf("%02X%02X%02X", instCODE[0], instCODE[1], instCODE[2])))
				return xerrors.Errorf("Failed to get Get property map (CLASSCODE:%+v): %w", instCODE, err)
			}
			for _, getProp := range getPropMap {
				for i := 0; i < len(instance.Props); i++ {
					if getProp == instance.Props[i].EPC {
						instance.Props[i].ImplementGet = true
					}
				}
			}
			// Inf property map create
			infPropMap, err := node.GetPropMap(instCODE, 0x9D)
			if err != nil {
				a.logger.Error("Get Inf property map Failed", zap.String("CLASS", fmt.Sprintf("%02X%02X%02X", instCODE[0], instCODE[1], instCODE[2])))
				return xerrors.Errorf("Failed to get Inf property map (CLASSCODE:%+v): %w", instCODE, err)
			}
			for _, infProp := range infPropMap {
				for i := 0; i < len(instance.Props); i++ {
					if infProp == instance.Props[i].EPC {
						instance.Props[i].ImplementInf = true
					} else {
						instance.Props[i].ImplementInf = false
					}
				}
			}
			node.Instances = append(node.Instances, instance)
		}
		a.DistNodes = append(a.DistNodes, node)
	}
	return nil
}

// NewAuditor create Auditor, test target devices with ECHONET Lite
// Configure logger and Node par dst, argument 1
func (a *Auditor) NewAuditor(dsts []net.IP) error {
	// file name config
	t := time.Now()
	TimeStr = fmt.Sprint(t.Year()) + "-" + fmt.Sprint(int(t.Month())) + "-" + fmt.Sprint(t.Day()) + "-" + fmt.Sprint(t.Minute()) + "-" + fmt.Sprint(t.Second())
	dirAuditorLog, fileAuditorLog := filepath.Split("echonet/" + TimeStr + "-" + "echonetlite.log")
	a.logger = util.InitLogger(dirAuditorLog + fileAuditorLog)
	if a.logger == nil {
		return xerrors.Errorf("Create new Auditor failed")
	}

	a.logger.Info("Create Auditor")

	err := a.AddDistNodes(dsts)
	if err != nil {
		return err
	}

	return nil
}

// RunEchonetPrompt execute ECHONET Lite prompt
func (a *Auditor) RunEchonetPrompt() {
	p := prompt.New(
		a.executorEchonet,
		a.completerEchonet,
		prompt.OptionTitle("VulnApplianceScanner"),
		prompt.OptionPrefix("(Input)> "),
	)
	p.Run()
}

// parser parse byte to ECHONET Lite frame
func parser(data []byte) (*FrameFormat, error) {
	var frame FrameFormat
	r := bytes.NewBuffer(data)
	err := binary.Read(r, binary.BigEndian, &frame.EHD1)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read EHD1: %w", err)
	}
	err = binary.Read(r, binary.BigEndian, &frame.EHD2)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read EHD2: %w", err)
	}
	err = binary.Read(r, binary.BigEndian, &frame.TID)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read TID: %w", err)
	}
	err = binary.Read(r, binary.BigEndian, &frame.SEOJ[0])
	err = binary.Read(r, binary.BigEndian, &frame.SEOJ[1])
	err = binary.Read(r, binary.BigEndian, &frame.SEOJ[2])
	if err != nil {
		return nil, xerrors.Errorf("Failed to read SEOJ: %w", err)
	}
	err = binary.Read(r, binary.BigEndian, &frame.DEOJ[0])
	err = binary.Read(r, binary.BigEndian, &frame.DEOJ[1])
	err = binary.Read(r, binary.BigEndian, &frame.DEOJ[2])
	if err != nil {
		return nil, xerrors.Errorf("Failed to read DEOJ: %w", err)
	}
	err = binary.Read(r, binary.BigEndian, &frame.ESV)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read ESV: %w", err)
	}
	err = binary.Read(r, binary.BigEndian, &frame.OPC)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read OPC: %w", err)
	}
	frame.VarGroups = make([]VarByteGroup, frame.OPC, frame.OPC)
	for i := 0; uint8(i) < uint8(frame.OPC); i++ {
		err = binary.Read(r, binary.BigEndian, &frame.VarGroups[i].EPC)
		if err != nil {
			return nil, xerrors.Errorf("Failed to read EPC: %w", err)
		}
		err = binary.Read(r, binary.BigEndian, &frame.VarGroups[i].PDC)
		if err != nil {
			return nil, xerrors.Errorf("Failed to read PDC: %w", err)
		}
		EDTlength := uint8(frame.VarGroups[i].PDC)
		if EDTlength > 0 {
			frame.VarGroups[i].EDT = make([]uint8, EDTlength, EDTlength)
			err = binary.Read(r, binary.BigEndian, &frame.VarGroups[i].EDT)
			if err != nil {
				return nil, xerrors.Errorf("Failed to read EDT: %w", err)
			}
		}
	}
	// OPCGet Exist
	err = binary.Read(r, binary.BigEndian, &frame.OPCG)
	if err == nil {
		frame.VarGroupsG = make([]VarByteGroup, frame.OPCG, frame.OPC)
		for i := 0; uint8(i) < uint8(frame.OPC); i++ {
			err = binary.Read(r, binary.BigEndian, &frame.VarGroupsG[i].EPC)
			if err != nil {
				return nil, xerrors.Errorf("Failed to read EPC: %w", err)
			}
			err = binary.Read(r, binary.BigEndian, &frame.VarGroupsG[i].PDC)
			if err != nil {
				return nil, xerrors.Errorf("Failed to read PDC: %w", err)
			}
			EDTlength := uint8(frame.VarGroupsG[i].PDC)
			if EDTlength > 0 {
				frame.VarGroupsG[i].EDT = make([]uint8, EDTlength, EDTlength)
				err = binary.Read(r, binary.BigEndian, &frame.VarGroupsG[i].EDT)
				if err != nil {
					return nil, xerrors.Errorf("Failed to read EDT: %w", err)
				}
			}
		}
	}
	return &frame, nil
}

// SendEchonet send ECHONET Lite packet
// Designate target device by argument 2, conn (net.Conn)
func SendEchonet(payload FrameFormat, conn net.Conn) error {
	_, err := conn.Write(echonetToByte(payload))
	if err != nil {
		return xerrors.Errorf("Failed to send ECHONET Lite packet: %w", err)
	}
	return nil
}

// SendEchonet receive ECHONET Lite packet
// Return packet frame as FrameFormat
func (a *Node) RecvEchonet() (FrameFormat, error) {
	var retFrame FrameFormat
	err := a.connRecv.SetDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		return retFrame, xerrors.Errorf("Setting Timeout Error: %w", err)
	}

	buffer := make([]byte, 4096)
	length, _, err := a.connRecv.ReadFromUDP(buffer)
	if err != nil {
		return retFrame, xerrors.Errorf("Failed to recieve ECHONET Lite packet: %w", err)
	}

	recv, err := parser(buffer[:length])
	if err != nil {
		return *recv, xerrors.Errorf("Failed to parse recieved ECHONET Lite packet: %w", err)
	} else if recv.EHD1 != 0x10 || recv.EHD2&0x80 != 0x80 {
		return *recv, xerrors.Errorf("Target device doesn't have ECHONET Lite Service: %w", err)
	}

	return *recv, nil
}

// change FrameFormat to []byte
func echonetToByte(echoFrame FrameFormat) []byte {
	var payloadBytes []byte
	payloadBytes = append(payloadBytes, echoFrame.EHD1)
	payloadBytes = append(payloadBytes, echoFrame.EHD2)
	payloadBytes = append(payloadBytes, uint8(echoFrame.TID>>8)&0xFF)
	payloadBytes = append(payloadBytes, uint8(echoFrame.TID&0xFF))

	for _, seoj := range echoFrame.SEOJ {
		payloadBytes = append(payloadBytes, seoj)
	}

	for _, deoj := range echoFrame.DEOJ {
		payloadBytes = append(payloadBytes, deoj)
	}

	payloadBytes = append(payloadBytes, echoFrame.ESV)
	payloadBytes = append(payloadBytes, echoFrame.OPC)
	for _, varGroup := range echoFrame.VarGroups {
		payloadBytes = append(payloadBytes, varGroup.EPC)
		payloadBytes = append(payloadBytes, varGroup.PDC)
		if varGroup.PDC != 0x00 {
			for _, edt := range varGroup.EDT {
				payloadBytes = append(payloadBytes, edt)
			}
		}
	}

	return payloadBytes
}

// CreateObject create the struct, Instance whose object code is objectCode(argument 1).
// Argument release designate Appendix version.
// Argument json is byte data of JSON.
// Return Instance and error
func (node *Node) CreateObject(objectCode [3]uint8, release string, json []byte) (Instance, error) {
	// retInstance is return Instance
	var retInstance Instance
	var err error

	node.logger.Info("Create object", zap.String("CLASS", fmt.Sprintf("%02X%02X%02X", objectCode[0], objectCode[1], objectCode[2])))

	definition, _, _, err = jsonparser.Get(json, "definitions")
	if err != nil {
		return retInstance, xerrors.Errorf("Invalid json data: %w", err)
	}

	retInstance.ClassCode = objectCode
	classCode := fmt.Sprintf("0x%02X%02X", objectCode[0], objectCode[1])
	//check exists of class
	_, _, _, err = jsonparser.Get(json, "devices", classCode)
	if err != nil {
		return retInstance, xerrors.Errorf("Failed to find class %s: %w", classCode, err)
	}

	//check property type is multiple or not
	classPathOneOf := []string{"devices", classCode, "oneOf"}
	classValue, _, _, err := jsonparser.Get(json, classPathOneOf...)
	if err == nil {
		_, err = jsonparser.ArrayEach(json, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
			from, err := jsonparser.GetString(valueArray, "validRelease", "from")
			to, err := jsonparser.GetString(valueArray, "validRelease", "to")
			if string(to) == "latest" {
				to = "M"
			}
			if from <= release && to >= release {
				classValue = valueArray
			}
		}, classPathOneOf...)
		if err != nil {
			return retInstance, xerrors.Errorf("Failed to choose version of class(Code:%s): %w", classCode, err)
		}
	} else {
		classValue, _, _, err = jsonparser.Get(json, "devices", classCode)
		if err != nil {
			return retInstance, xerrors.Errorf("Failed to parse class(Code:%s): %w", classCode, err)
		}
	}

	className, err := jsonparser.GetString(classValue, "className", "en")
	if err != nil {
		return retInstance, xerrors.Errorf("Failed to find class name of %s: %w", classCode, err)
	}
	retInstance.ClassName = className

	// get EPC
	err = jsonparser.ObjectEach(classValue, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		var prop Property
		epc, err := strconv.ParseInt(string(key), 0, 16)
		if err != nil {
			return xerrors.Errorf("Incorrect EPC %d :%w", epc, err)
		}
		prop.EPC = uint8(epc)
		retInstance.Props = append(retInstance.Props, prop)
		return nil
	}, "elProperties")
	if err != nil {
		return retInstance, xerrors.Errorf("Failed to parse Property Code at %s: %w", className, err)
	}

	// parse Properties
	for i, prop := range retInstance.Props {
		epc := retInstance.Props[i].EPC
		retInstance.Props[i], err = node.getPropertyInfo(prop, classValue, release)
		if err != nil {
			return retInstance, xerrors.Errorf("Getting Property Info Error: %w", err)
		}
		retInstance.Props[i].EPC = epc
	}

	// If retInstance is not the Instance which is nodeProfileObject(class group code is 0x0E), SuperObject(class group code is 0x00) or UserDefinedObject(class group code is 0xF0),
	// retInstance is the child of SuperObject.
	// That is why create and merge object SuperObject.
	if !(retInstance.ClassCode[0] == 0x0E || retInstance.ClassCode[0] == 0x0F) && !(retInstance.ClassCode[1] == 0x00 && retInstance.ClassCode[0] == 0x00) {
		recv, err := node.CreateObject([3]uint8{0x00, 0x00, 0x00}, release, json)
		if err != nil {
			return recv, xerrors.Errorf("Failed to Create SuperClass Object: %w", err)
		}
		for _, propSuperClass := range recv.Props {
			exist := false
			for _, prop := range retInstance.Props {
				if propSuperClass.EPC == prop.EPC {
					exist = true
					break
				}
			}
			if !exist {
				retInstance.Props = append(retInstance.Props, propSuperClass)
			}
		}
	}

	return retInstance, nil
}

// parser property map EDT into Properties []uint8
func parsePropMap(propertyMapEDT []uint8) ([]uint8, error) {
	var retProp []uint8
	length := propertyMapEDT[0]
	if length < 16 {
		for i := 1; i < int(length)+1; i++ {
			retProp = append(retProp, propertyMapEDT[i])
		}
	} else {
		// Create Property map if the number of properties is over 15
		// Specification of property map is appendix 1 of "https://echonet.jp/wp/wp-content/uploads/pdf/General/Standard/Release/Release_M_en/Appendix_Release_M_E.pdf"
		for underDigit := 1; underDigit < 17; underDigit++ {
			for upperDigit := 0; upperDigit < 8; upperDigit++ {
				//
				if propertyMapEDT[underDigit]&uint8(1<<upperDigit) != 0 {
					retProp = append(retProp, uint8((upperDigit+8)*0x10|(underDigit-1)))
				}
			}
		}
	}
	if len(retProp) != int(length) {
		return retProp, xerrors.Errorf("Invalid property map")
	}
	return retProp, nil
}

// PrintInfo print property data of argument 1, data.
// if argument 2, inputMode, is True, input EDT and return EDT input as []uint8
func (node *Node) PrintInfo(data interface{}, inputMode bool) ([]uint8, error) {
	// retData is return data []uint8 when inputMode == true
	var retData []uint8

	if value, ok := data.(Property); ok {
		if len(value.Data) > 1 {
			fmt.Printf("(ECHONET Lite:Information) > Property '%s' has multiple type of Data\n", value.PropertyName)
			for i, propertyData := range value.Data {
				fmt.Printf("(ECHONET Lite:Information) > Type %d\n", i)
				node.PrintInfo(propertyData, false)
			}
			if inputMode {
				fmt.Printf("(ECHONET Lite:Information) > Choose type\n")
				fmt.Printf("(Input) > ")
				buf := nextLine()
				index, err := strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				} else if index < 1 || index > int64(len(value.Data)) {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is overflow or underflow")
				}
				recvdata, err := node.PrintInfo(value.Data[index], true)
				if err != nil {
					node.logger.Error("Couldn't print information of data")
					return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
				}
				for _, data := range recvdata {
					retData = append(retData, data)
				}
			}
			return retData, nil
		} else {
			recvdata, err := node.PrintInfo(value.Data[0], inputMode)
			if err != nil {
				node.logger.Error("Couldn't print information of data")
				return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
			}
			for _, data := range recvdata {
				retData = append(retData, data)
			}
			return retData, nil
		}
	} else if value, ok := data.([]interface{}); ok {
		if len(value) > 1 {
			fmt.Printf("(ECHONET Lite:Information) > There are Multiple Type")
			for i, multiType := range value {
				fmt.Printf("(ECHONET Lite:Information) > Type %d\n", i)
				node.PrintInfo(multiType, false)
			}
			if inputMode {
				fmt.Printf("(ECHONET Lite:Information) > Choose type N\n")
				fmt.Printf("(Input) > ")
				buf := nextLine()
				index, err := strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				} else if index < 1 || index > int64(len(value)) {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is overflow or underflow")
				}
				recvdata, err := node.PrintInfo(value[index], true)
				if err != nil {
					node.logger.Error("Couldn't print information of data")
					return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
				}
				for _, data := range recvdata {
					retData = append(retData, data)
				}
				return retData, nil
			}
		} else {
			recvdata, err := node.PrintInfo(value[0], inputMode)
			if err != nil {
				node.logger.Error("Couldn't print information of data")
				return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
			}
			for _, data := range recvdata {
				retData = append(retData, data)
			}
			return retData, nil
		}
	} else if value, ok := data.(Number); ok {
		var retNum int64
		fmt.Printf("--- NUMBER ---\n")
		fmt.Printf("> Format: %s\n", value.format)
		// enum type
		if len(value.enum) > 0 {
			fmt.Printf("> Number is below\n")
			for _, enum := range value.enum {
				fmt.Printf("%02X ", enum)
			}
			fmt.Printf("--------------\n")
			if inputMode {
				fmt.Printf("(ECHONET Lite:Information) > Input Hex Number\n")
				fmt.Printf("(Input) > ")
				buf := "0x" + nextLine()
				hexNum, err := strconv.ParseInt(buf, 0, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				for _, retNum = range value.enum {
					if retNum == hexNum {
						if strings.HasSuffix(value.format, "int8") {
							return []uint8{uint8(retNum)}, nil
						} else if strings.HasSuffix(value.format, "int16") {
							return []uint8{uint8(retNum >> 8), uint8(retNum) & 0xFF}, nil
						} else if strings.HasSuffix(value.format, "int32") {
							return []uint8{uint8(retNum >> 24), uint8(retNum>>16) & 0xFF, uint8(retNum>>8) & 0xFF, uint8(retNum) & 0xFF}, nil
						} else {
							return nil, xerrors.Errorf("Invalid format of Property")
						}
					}
				}
				return nil, xerrors.Errorf("Invalid Number")
			}
			return retData, nil
		} else {
			fmt.Printf("> Minimum: %d, Maximum: %d\n", value.minimum, value.maximum)
			fmt.Printf("> Unit: %s\n", value.unit)
			if value.multipleOf != 0 {
				fmt.Printf("> Multiple: %f\n", value.multipleOf)
			}
			fmt.Printf("--------------\n")
			if inputMode {
				fmt.Printf("(ECHONET Lite:Information) > Input Number\n")
				fmt.Printf("(Input) > ")
				buf := nextLine()
				retNum, err := strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				if strings.HasSuffix(value.format, "int8") {
					return []uint8{uint8(retNum)}, nil
				} else if strings.HasSuffix(value.format, "int16") {
					return []uint8{uint8(retNum >> 8), uint8(retNum) & 0xFF}, nil
				} else if strings.HasSuffix(value.format, "int32") {
					return []uint8{uint8(retNum >> 24), uint8(retNum>>16) & 0xFF, uint8(retNum>>8) & 0xFF, uint8(retNum) & 0xFF}, nil
				} else {
					return nil, xerrors.Errorf("Invalid format of Property")
				}
			}
			return retData, nil
		}
	} else if value, ok := data.(State); ok {
		fmt.Printf("--- STATE ---\n")
		for _, enum := range value.enum {
			fmt.Printf("> 0x%X means %s\n", enum.edt, enum.state)
		}
		fmt.Printf("-------------\n")
		if inputMode {
			fmt.Printf("(ECHONET Lite:Information) > Input EDT Hex Number\n")
			fmt.Printf("(Input) > ")
			buf := "0x" + nextLine()
			hexNum, err := strconv.ParseInt(buf, 0, 64)
			if err != nil {
				node.logger.Error("Input number is invalid")
				return nil, xerrors.Errorf("Input number is invalid: %w", err)
			}
			for _, enum := range value.enum {
				if enum.edt == hexNum {
					if value.size == 0 {
						retData = append(retData, uint8(hexNum))
					} else {
						for i := value.size - 1; i >= 0; i-- {
							retData = append(retData, uint8(hexNum>>(i*8))&0xFF)
						}
					}
				}
			}
			return retData, nil
		}
		return nil, nil
	} else if value, ok := data.(Level); ok {
		fmt.Printf("--- LEVEL ---\n")
		fmt.Printf("> Base: %s\n", value.base)
		fmt.Printf("> Maximum: %s+%02X\n", value.base, value.maximum)
		fmt.Printf("-------------\n")
		if inputMode {
			fmt.Printf("(ECHONET Lite:Information) > Input Hex Number\n")
			fmt.Printf("(ECHONET Lite:Information) > e.g. %s\n", value.base[2:])
			fmt.Printf("(Input) > ")
			buf := nextLine()
			num, err := strconv.ParseInt(buf, 10, 64)
			if err != nil {
				node.logger.Error("Input number is invalid")
				return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
			}
			retData = append(retData, uint8(num))
			return retData, nil
		}
		return nil, nil
	} else if value, ok := data.(Raw); ok {
		fmt.Printf("--- RAW ---\n")
		fmt.Printf("> Minimum Length:%02X Byte\n> Maximum Length:%02X Byte\n", value.minSize, value.maxSize)
		fmt.Printf("-----------\n")
		if inputMode {
			fmt.Printf("(ECHONET Lite:Information) > Input Size\n")
			fmt.Printf("(Input) > ")
			buf := nextLine()
			num, err := strconv.ParseInt(buf, 10, 64)
			if err != nil {
				node.logger.Error("Input number is invalid")
				return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
			}
			retData = make([]uint8, num, num)
			for i := 0; int64(i) < num; i++ {
				fmt.Printf("(ECHONET Lite:Information) > Input data at %d Byte\n", i+1)
				fmt.Printf("(ECHONET Lite:Information) > e.g. 8F\n")
				fmt.Printf("(Input) > ")
				byteData, err := strconv.ParseInt(nextLine(), 16, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input HEX number: %w", err)
				}
				retData[i] = uint8(byteData)
			}
			return retData, nil
		}
		return nil, nil
	} else if value, ok := data.(Object); ok {
		fmt.Printf("--- OBJECT ---\n")
		fmt.Printf("(ECHONET Lite:Information) > Data type OBJECT\n")
		fmt.Printf("(ECHONET Lite:Information) > Element Length is %d", len(value.element))
		fmt.Printf("> ")
		for _, el := range value.element {
			fmt.Printf("%s ", el.name)
		}
		for i, el := range value.element {
			fmt.Printf("(ECHONET Lite:Information) > Element %d: %s\n", i, el.name)
			recv, err := node.PrintInfo(el.data, inputMode)
			if err != nil {
				node.logger.Error("Couldn't print information of data")
				return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
			}
			if inputMode {
				for _, num := range recv {
					retData = append(retData, num)
				}
			}
		}
		return retData, nil

	} else if value, ok := data.(Array); ok {
		fmt.Printf("--- ARRAY ---\n")
		fmt.Printf("> Each size is %d Byte", value.itemSize)
		fmt.Printf("> MinimumItems: %d, MaximumItems: %d\n", value.minItems, value.maxItems)
		fmt.Printf("-------------\n")
		if inputMode {
			fmt.Printf("(ECHONET Lite:Information) > Input Array Index Size\n")
			fmt.Printf("(Input) > ")
			buf := nextLine()
			indexNum, err := strconv.ParseInt(buf, 10, 64)
			if err != nil {
				node.logger.Error("Input number is invalid")
				return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
			}
			for i := 0; int64(i) < indexNum; i++ {
				recv, err := node.PrintInfo(value.data, inputMode)
				if err != nil {
					node.logger.Error("Couldn't print information of data")
					return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
				}
				for _, num := range recv {
					retData = append(retData, num)
				}
			}
			return retData, nil
		}
		return nil, nil
	} else if value, ok := data.(Bitmap); ok {
		retData = make([]uint8, value.size, value.size)
		fmt.Printf("--- BITMAP ---\n")
		fmt.Printf("(ECHONET Lite:Information) > Size is %d Byte\n", value.size)
		for i, bitmap := range value.bitmaps {
			fmt.Printf("--- %d ---\n", i)
			recv, err := node.PrintInfo(bitmap, inputMode)
			if err != nil {
				node.logger.Error("Couldn't print information of data")
				return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
			}
			fmt.Printf("---------\n")
			if inputMode {
				retData[bitmap.index-1] = retData[bitmap.index-1] | recv[0]
			}
		}
		return retData, nil
	} else if value, ok := data.(ElBitmap); ok {
		fmt.Printf("(ECHONET Lite:Information) > Name %s\n", value.descriptions)
		recv, err := node.PrintInfo(value.value, inputMode)
		if err != nil {
			node.logger.Error("Couldn't print information of data")
			return nil, xerrors.Errorf("Couldn't print information of data: %w", err)
		}
		if inputMode {
			var shift int64

			hexNum := recv[len(recv)-1]
			bitmask := value.bitmask

			for i := 0; i < 9; i++ {
				shift = int64(i)
				if bitmask%2 == 1 {
					break
				}
				bitmask = bitmask >> 1
			}

			return []uint8{hexNum << uint8(shift) & uint8(bitmask)}, nil
		}
		return nil, nil
	} else if value, ok := data.(NumericValues); ok {
		fmt.Printf("--- NumericValue ---\n")
		fmt.Printf("(ECHONET Lite:Information) > Size is %d byte \n", value.size)
		fmt.Printf("--- Numbers ---\n")
		for _, nNumber := range value.enum {
			fmt.Printf("> %02X\n is mean %f", nNumber.edt, nNumber.value)
		}
		fmt.Printf("---------------\n")
		if inputMode {
			fmt.Printf("(ECHONET Lite:Information) > Input Hex Number\n")
			fmt.Printf("(ECHONET Lite:Information) > e.g. %02X\n", value.enum[0].edt)
			fmt.Printf("(Input) > ")
			buf := "0x" + nextLine()
			hexNum, err := strconv.ParseInt(buf, 0, 64)
			if err != nil {
				node.logger.Error("Input number is invalid")
				return nil, xerrors.Errorf("Input number is invalid. Please input HEX number: %w", err)
			}
			return []uint8{uint8(hexNum)}, nil
		}
		return nil, nil
	} else if value, ok := data.(DateTime); ok {
		fmt.Printf("--- Time ---\n")
		switch value.size {
		case 2:
			fmt.Printf("(ECHONET Lite:Information) > Manth:Day\n")
		case 3:
			fmt.Printf("(ECHONET Lite:Information) > Hour:Minute:Second\n")
		case 4:
			fmt.Printf("(ECHONET Lite:Information) > Year:Manth:Day\n")
		case 6:
			fmt.Printf("(ECHONET Lite:Information) > Year:Manth:Day:Hour:Minute\n")
		case 7:
			fmt.Printf("(ECHONET Lite:Information) > Year:Manth:Day:Hour:Minute:Second\n")
		}
		fmt.Printf("------------\n")
		if inputMode {
			if value.size == 4 || value.size == 6 || value.size == 7 {
				fmt.Printf("(ECHONET Lite:Information) > Input Year\n")
				fmt.Printf("(Input) > ")
				buf := nextLine()
				num, err := strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				retData = append(retData, uint8(num&0xFF))
				retData = append(retData, uint8((num>>8)&0xFF))
			}
			if value.size != 3 {
				fmt.Printf("(ECHONET Lite:Information) > Input Month\n")
				fmt.Printf("(Input) > ")
				buf := nextLine()
				num, err := strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				retData = append(retData, uint8(num))

				fmt.Printf("(ECHONET Lite:Information) > Input Day\n")
				fmt.Printf("(Input) > ")
				buf = nextLine()
				num, err = strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				retData = append(retData, uint8(num))
			}
			if value.size == 3 || value.size == 6 || value.size == 7 {
				fmt.Printf("(ECHONET Lite:Information) > Input Hour\n")
				fmt.Printf("(Input) > ")
				buf := nextLine()
				num, err := strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				retData = append(retData, uint8(num))

				fmt.Printf("(ECHONET Lite:Information) > Input Munute\n")
				fmt.Printf("(Input) > ")
				buf = nextLine()
				num, err = strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				retData = append(retData, uint8(num))
			}
			if value.size == 3 || value.size == 7 {
				fmt.Printf("(ECHONET Lite:Information) > Input Second\n")
				fmt.Printf("(Input) > ")
				buf := nextLine()
				num, err := strconv.ParseInt(buf, 10, 64)
				if err != nil {
					node.logger.Error("Input number is invalid")
					return nil, xerrors.Errorf("Input number is invalid. Please input DECIMAL number: %w", err)
				}
				retData = append(retData, uint8(num))
			}
			return retData, nil
		}
	}
	return nil, nil
}

// GetPropMap get property map from the instance designated by argument 1, classCode..
// argument 2, mapEpc, designate the property map.
// 0x9D: StateAnnounce, 0x9E: Set, 0x9F: Get
// Return EPCs as []uint8
func (node *Node) GetPropMap(classCode [3]uint8, mapEpc uint8) ([]uint8, error) {
	payload := FrameFormat{
		EHD1: 0x10,
		EHD2: 0x81,
		SEOJ: nodeProfileEOJ,
		DEOJ: classCode,
		ESV:  0x62,
		OPC:  0x01,
		VarGroups: []VarByteGroup{
			{
				EPC: mapEpc,
				PDC: 0x00,
				EDT: nil,
			},
		},
	}

	go func() {
		SendEchonet(payload, node.connSend)
	}()
	recvFrame, err := node.RecvEchonet()
	if err != nil {
		node.logger.Error("Couldn't receive the packet")
		return nil, xerrors.Errorf("Couldn't receive the packet: %w", err)
	}
	epcs, err := parsePropMap(recvFrame.VarGroups[0].EDT)
	if err != nil {
		node.logger.Error("Parse property map Failed")
	}
	return epcs, nil
}

// Communicate communicate with target PC in ECHONET Lite
// Nomal Mode: Create and send ECHOENT Lite packet base on supecification
// Test Mode: Create Any packet
func (node *Node) Communicate() error {
	node.logger.Info("Start to communicate", zap.String("IPaddr", node.ip.String()))

	// Instance you communicate
	var communicateInstance Instance

	testMode := false
	rand.Seed(time.Now().UnixNano())

	fmt.Printf("\n(ECHONET Lite:Information) > Test Mode:0   Normal Mode:1\n")
	for {
		fmt.Printf("(Input) > ")
		testNum, err := strconv.ParseInt(nextLine(), 10, 64)
		if err != nil { // ParseInt error
			fmt.Printf("(ECHONET Lite:Error) > Invalid Number\n")
		} else if testNum > 1 || testNum < 0 { // testNum is not 1 nor 0
			fmt.Printf("(ECHONET Lite:Error) > Out of range\n")
		} else {
			if testNum == 0 {
				testMode = true
			}
			break
		}
	}

	for {
		payload := FrameFormat{
			EHD1: 0x10,
			EHD2: 0x81,
			TID:  uint16(rand.Int()),
			SEOJ: nodeProfileEOJ,
		}

		// choose instance you communicate. designate by Object CODE
		fmt.Println("\n\n(ECHONET Lite:Information) > Input ECHONET Lite Object CODE you wanna communicate with ECHONET Lite")
		fmt.Printf("   --------- Instances ---------\n")
		for i, inst := range node.Instances {
			fmt.Printf("   > index[%d] CODE:0x%02X%02X%02X, Name:%s\n", i+1, inst.ClassCode[0], inst.ClassCode[1], inst.ClassCode[2], inst.ClassName)
		}
		fmt.Printf("   -----------------------------\n")
		fmt.Printf("(ECHONET Lite:Information) > If you wanna communicate %s, you should Input index '1'\n", node.Instances[0].ClassName)
		fmt.Println("(ECHONET Lite:Information) > If you wanna EXIT, enter '0'")

		var index int64
		for {
			fmt.Printf("(Input) > ")
			indexBuf, err := strconv.ParseInt(nextLine(), 10, 64)
			index = indexBuf
			if err != nil || index > int64(len(node.Instances)) || index < 0 { // index out of range
				fmt.Printf("(ECHONET Lite:Error) > Invalid index\n")
				continue
			} else if index == 0 { // index 0 means END of communicate
				return nil
			}
			break
		}
		communicateInstance = node.Instances[index-1]
		payload.DEOJ = communicateInstance.ClassCode

		// suspend judge END of communication during input EPC or EDT
		suspend := false
		if !testMode {
			fmt.Printf("\n(ECHONET Lite:Information)> Input ESV with hexnumber\n")
			fmt.Printf("(Input:ESV) > ")
			num, err := strconv.ParseInt(nextLine(), 16, 64)
			if err != nil {
				fmt.Printf("(ECHONET Lite:Error) > Invalid number\n")
				continue
			}
			inputMode := false
			for {
				if num == 0x60 || num == 0x61 {
					inputMode = true
					fmt.Printf("\n(ECHONET Lite:Information)> Set Properties are\n")
					for _, prop := range communicateInstance.Props {
						if prop.ImplementSet {
							fmt.Printf("> EPC: %02X, Name: %s\n", prop.EPC, prop.PropertyName)
						}
					}
					break
				} else if num == 0x62 {
					fmt.Printf("\n(ECHONET Lite:Information)> Get Properties are\n")
					for _, prop := range communicateInstance.Props {
						if prop.ImplementGet {
							fmt.Printf("> EPC: %02X, Name: %s\n", prop.EPC, prop.PropertyName)
						}
					}
					break
				} else {
					fmt.Printf("(ECHONET Lite:Error) > Invalid ESV\n")
				}
			}
			payload.ESV = uint8(num)
			fmt.Printf("\n(ECHONET Lite:Information) > Input OPC (Operation Property COUNTER) with HEX number\n")
			fmt.Printf("(Input:OPC)> ")
			num, err = strconv.ParseInt(nextLine(), 16, 64)
			if err != nil {
				fmt.Printf("(ECHONET Lite:Error) > Invalid number\n")
				continue
			}
			payload.OPC = uint8(num)
			for i := 0; int64(i) < num; i++ {
				fmt.Printf("(ECHONET Lite:Information)> Input EPC with HEX number\n")
				fmt.Printf("(ECHONET Lite:Information)> Type 'END' to suspend communication\n")
				fmt.Printf("(Input:EPC%d)> ", i+1)
				buf := nextLine()
				if strings.Contains(buf, "END") {
					suspend = true
					break
				}
				epc, err := strconv.ParseInt(buf, 16, 64)
				if err != nil {
					fmt.Printf("(ECHONET Lite:Error) > Invalid number\n")
					return xerrors.Errorf("Invalid number: %w", err)
				}
				var recv []uint8
				for _, propComm := range communicateInstance.Props {
					if propComm.EPC == uint8(epc) {
						recv, err = node.PrintInfo(propComm, inputMode)
						if err != nil {
							node.logger.Error(fmt.Sprintf("Print information failed"))
						}
					}
				}
				varGroup := VarByteGroup{
					EPC: uint8(epc),
					PDC: uint8(len(recv)),
					EDT: recv,
				}
				payload.VarGroups = append(payload.VarGroups, varGroup)
			}
			if suspend == true {
				return nil
			}
		} else { // Test Mode
			for {
				fmt.Printf("\n(ECHONET Lite:Information)> Input HEX number\n")
				fmt.Printf("(Input)> ")
				varByte := nextLine()
				index := 0
				esv, err := strconv.ParseUint(varByte[index:index+2], 16, 64)
				index += 2
				if err != nil {
					node.logger.Error("Invalid Number")
					continue
				}
				payload.ESV = uint8(esv)
				opc, err := strconv.ParseUint(varByte[index:index+2], 16, 64)
				index += 2
				if err != nil {
					node.logger.Error("Invalid Number")
					continue
				}
				payload.OPC = uint8(opc)
				epc, err := strconv.ParseUint(varByte[index:index+2], 16, 64)
				index += 2
				if err != nil {
					node.logger.Error("Invalid Number")
					continue
				}
				pdc, err := strconv.ParseUint(varByte[index:index+2], 16, 64)
				index += 2
				if err != nil {
					node.logger.Error("Invalid Number")
					continue
				}
				var edt []uint8
				invalidNum := false
				for i := index; i < len(varByte)-1; i += 2 {
					buf, err := strconv.ParseUint(varByte[i:i+2], 16, 64)
					if err != nil {
						invalidNum = true
						node.logger.Error("Invalid Number")
						break
					}
					edt = append(edt, uint8(buf))

				}
				payload.VarGroups = []VarByteGroup{
					{
						EPC: uint8(epc),
						PDC: uint8(pdc),
						EDT: edt,
					},
				}
				if invalidNum {
					continue
				}
				break
			}
		}
		node.logger.Info("Send packet", zap.String("payload", fmt.Sprintf("%+v", payload)))
		fmt.Printf("--- Send ---\n")
		printPacket(payload)
		fmt.Printf("------------\n")
		go func() {
			SendEchonet(payload, node.connSend)
		}()
		recv, _ := node.RecvEchonet()
		node.logger.Info("receive packet", zap.String("payload", fmt.Sprintf("%+v", recv)))
		fmt.Printf("--- Recv ---\n")
		printPacket(recv)
		fmt.Printf("------------\n")
	}
}

// print FrameFormat
func printPacket(payload FrameFormat) error {
	fmt.Printf("> EHD1:   %02X\n", payload.EHD1)
	fmt.Printf("> EHD2:   %02X\n", payload.EHD2)
	fmt.Printf("> TID:    %02X\n", payload.TID)
	fmt.Printf("> SEOJ:   %02X\n", payload.SEOJ)
	fmt.Printf("> DEOJ:   %02X\n", payload.DEOJ)
	fmt.Printf("> ESV:    %02X\n", payload.ESV)
	if payload.VarGroupsG != nil {
		fmt.Printf("> OPCSet: %02X\n", payload.OPC)
	} else {
		fmt.Printf("> OPC:    %02X\n", payload.OPC)
	}
	for i, varGroup := range payload.VarGroups {
		i++
		fmt.Printf(">  EPC%d:  		%02X\n", i, varGroup.EPC)
		fmt.Printf(">  PDC%d:  		%02X\n", i, varGroup.PDC)
		if varGroup.EDT != nil {
			fmt.Printf(">  EDT%d:  		%02X\n", i, varGroup.EDT)
		}
	}
	if payload.VarGroupsG != nil {
		fmt.Printf("> OPCGet: %02X\n", payload.OPC)
		for i, varGroup := range payload.VarGroups {
			fmt.Printf(">  EPC%d:  		%02X\n", i, varGroup.EPC)
			fmt.Printf(">  PDC%d:  		%02X\n", i, varGroup.PDC)
			if varGroup.EDT != nil {
				fmt.Printf(">  EDT%d:  		%02X\n", i, varGroup.EDT)
			}
		}
	}
	return nil
}

//func (a *Node) GetInstanceAll(dstIP []net.IP) error {
//	var err error
//
//	payload := FrameFormat{
//		EHD1: 0x10,
//		EHD2: 0x81,
//		SEOJ: nodeProfileEOJ,
//		DEOJ: [3]uint8{0x0E, 0xF0, 0x01},
//		OPC:  0x01,
//		ESV:  0x62,
//		VarGroups: []VarByteGroup{
//			{
//				EPC: 0xD6,
//				PDC: 0x00,
//			},
//		},
//	}
//
//	go func() {
//		SendEchonet(payload, a.connSend)
//	}()
//
////TODO RecvEchonet()
//	a.connRecv, err = net.ListenUDP("udp", udpAddr)
//
//	if err != nil {
//		payload.DEOJ = [3]uint8{0x0E, 0xF0, 0x02}
//		go func() {
//			SendEchonet(payload, a.connSend)
//		}()
////TODO RecvEchonet()
//		a.connRecv, err = net.ListenUDP("udp", udpAddr)
//		if err != nil {
//			return xerrors.Errorf("Couldn't communicate with Node Profile Object: %w", err)
//		}
//	}
////TODO RecvEchonet()
//	recv, err := a.RecvEchonet()
//	if err != nil {
//		return xerrors.Errorf("Couldn't Receive ECHONET Lite packet")
//	}
//	err = CheckFlowValidation(payload, recv)
//	if err != nil {
//		return xerrors.Errorf("Invalid Flow: %w", err)
//	}
//	a.Instances, err = parseInstanceList(recv.VarGroups[0].EDT)
//
//	for _, inst := range a.Instances {
//		recvInst, err := CreateObject(inst.ClassCode, rel, jsonAll)
//		if err != nil {
//			return xerrors.Errorf("Failed to get property Data: %w", err)
//		}
//		a.Instances = append(a.Instances, recvInst)
//	}
//	return nil
//}
//

// parseInstanceList EPC: 0xD5, 0xD6
func parseInstanceList(edt []uint8) ([]Instance, error) {
	var retInstances []Instance

	numberInstance := edt[0]

	for i := 0; i < int(numberInstance); i += 3 {
		var inst Instance
		inst.ClassCode = [3]uint8{edt[i], edt[i+1], edt[i+2]}
		retInstances = append(retInstances, inst)
	}
	return retInstances, nil
}

// TODO 使われてない
func (a *Node) GetProp(deoj [3]uint8, seoj [3]uint8, props ...uint8) (FrameFormat, error) {
	var properties []VarByteGroup

	payload := FrameFormat{
		EHD1: 0x10,
		EHD2: 0x81,
		SEOJ: seoj,
		DEOJ: deoj,
		TID:  uint16(rand.Intn(65535)),
		ESV:  0x62,
		OPC:  uint8(len(props)),
	}

	for i, prop := range props {
		properties[i].EPC = prop
		properties[i].PDC = 0x00
	}
	payload.VarGroups = properties

	err := SendEchonet(payload, a.connSend)
	if err != nil {
		return payload, xerrors.Errorf("Failed to send ECHONET Lite packet: %w", err)
	}
	recv, err := a.RecvEchonet()
	if err != nil {
		return payload, xerrors.Errorf("Failed to send ECHONET Lite packet: %w", err)
	}

	return recv, nil
}
