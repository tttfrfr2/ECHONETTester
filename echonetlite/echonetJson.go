package echonetlite

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/buger/jsonparser"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

func (node *Node) getPropertyInfo(prop Property, json []byte, rel string) (Property, error) {
	var retProp Property

	retProp.EPC = prop.EPC
	epc := fmt.Sprintf("0x%02X", prop.EPC)

	var dataValue []byte
	_, _, _, err := jsonparser.Get(json, "elProperties", epc, "oneOf")
	if err == nil {
		// when property has multi patern
		_, err = jsonparser.ArrayEach(json, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
			from, err := jsonparser.GetString(valueArray, "validRelease", "from")
			to, err := jsonparser.GetString(valueArray, "validRelease", "to")
			if string(to) == "latest" {
				to = "M"
			}
			if from <= rel && to >= rel {
				dataValue = valueArray
			} else {
				err = xerrors.Errorf("Invalid Version")
			}
		}, "elProperties", epc, "oneOf")
		if err != nil {
			node.logger.Error("Property version is Invalid")
			return retProp, xerrors.Errorf("Failed to choose version of property(Code:%s): %w", epc, err)
		}
	} else {
		// when property has only one patern
		dataValue, _, _, err = jsonparser.Get(json, "elProperties", epc)
		if err != nil {
			node.logger.Error("There are no Property", zap.String("EPC", fmt.Sprintf("0x%02X", epc)))
			return retProp, xerrors.Errorf("Failed to read object whose key is %s: %w", epc, err)
		}
	}

	_, _, _, err = jsonparser.Get(dataValue, "data", "oneOf")
	if err == nil {
		// when data has multi patern
		_, err = jsonparser.ArrayEach(dataValue, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
			from, err := jsonparser.GetString(valueArray, "validRelease", "from")
			to, err := jsonparser.GetString(valueArray, "validRelease", "to")
			if string(to) == "latest" {
				to = "M"
			}
			if from <= rel && to >= rel {
				dataValue = valueArray
			} else {
				err = xerrors.Errorf("Invalid Version")
			}

		}, "data", "oneOf")
		if err != nil {
			node.logger.Error("Property version is Invalid")
			return retProp, xerrors.Errorf("Failed to choose version of property(Code:%s): %w", epc, err)
		}
	} else {
		// when data has only one patern
		dataValue, _, _, err = jsonparser.Get(dataValue)
		if err != nil {
			return retProp, xerrors.Errorf("Failed to find key \"data\": %w", err)
		}
	}
	retProp, err = node.parseMetaData(dataValue, epc)
	if err != nil {
		node.logger.Error("Invalid meta data")
		return retProp, xerrors.Errorf("Failed to parse meta data of EPC(%s): %w", epc, err)
	}

	dataValue, _, _, err = jsonparser.Get(dataValue, "data")
	datas, err := node.parseData(dataValue, rel)
	if err != nil {
		node.logger.Error("Invalid json data")
		return retProp, xerrors.Errorf("Failed to parse data of json: %w", err)
	}

	for _, data := range datas {
		retProp.Data = append(retProp.Data, data)
	}

	return retProp, nil
}

func (node *Node) parseData(json []byte, rel string) ([]interface{}, error) {
	var retData []interface{}
	var err error
	valueOneOf, _, _, err := jsonparser.Get(json, "oneOf")
	if err == nil {
		_, err = jsonparser.ArrayEach(valueOneOf, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
			elements, _ := node.parseData(valueArray, rel)
			for _, element := range elements {
				retData = append(retData, element)
			}
		})
		return retData, nil
	} else {
		typeProp, _ := jsonparser.GetString(json, "type")

		switch {
		//type number
		case typeProp == "number":
			var elData Number
			elData.format, _ = jsonparser.GetString(json, "format")
			elData.maximum, _ = jsonparser.GetInt(json, "maximum")
			elData.minimum, _ = jsonparser.GetInt(json, "minimum")
			elData.unit, _ = jsonparser.GetString(json, "unit")
			enums, _, _, err := jsonparser.Get(json, "enum")
			if err == nil {
				var buf []byte
				for i := 0; ; i++ {
					if enums[i] == ',' || enums[i] == ']' {
						atoi, _ := strconv.Atoi(string(buf))
						elData.enum = append(elData.enum, int64(atoi))
						buf = nil
						if enums[i] == ']' {
							break
						}

					} else if enums[i] != '[' {
						buf = append(buf, enums[i])
					}
				}
			}
			retData = append(retData, elData)
			return retData, nil

		//type state
		case typeProp == "state":
			var elData State
			elData.size, err = jsonparser.GetInt(json, "size")

			if elData.size == 0 {
				elData.size = 1
			}
			jsonparser.ArrayEach(json, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
				var e enumber
				_, err = jsonparser.GetString(valueArray, "edt")
				if err == nil {
					edt, _ := jsonparser.GetString(valueArray, "edt")
					e.edt, err = strconv.ParseInt(edt, 0, 64)
				} else {
					edt, _ := jsonparser.GetInt(valueArray, "edt")
					e.edt = int64(edt)
				}
				e.state, _ = jsonparser.GetString(valueArray, "state", "en")
				e.readOnly, _ = jsonparser.GetBoolean(valueArray, "readOnly")
				elData.enum = append(elData.enum, e)
			}, "enum")
			retData = append(retData, elData)
			return retData, nil

		//type level
		case typeProp == "level":
			var elData Level
			elData.base, _ = jsonparser.GetString(json, "base")
			max, _ := jsonparser.GetInt(json, "maximum")
			elData.maximum = uint64(max)
			retData = append(retData, elData)
			return retData, nil

		//type raw
		case typeProp == "raw":
			var elData Raw
			elData.minSize, _ = jsonparser.GetInt(json, "minSize")
			elData.maxSize, _ = jsonparser.GetInt(json, "maxSize")
			retData = append(retData, elData)
			return retData, nil

		//type object
		case typeProp == "object":
			var elData Object
			_, err := jsonparser.ArrayEach(json, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
				var elObject ElObject
				elObject.name, _ = jsonparser.GetString(valueArray, "name")
				valueElement, _, _, _ := jsonparser.Get(valueArray, "element")
				_, _, _, err = jsonparser.Get(valueElement, "oneOf")
				if err == nil {
					_, err = jsonparser.ArrayEach(valueElement, func(valueArr []byte, dataType jsonparser.ValueType, offset int, err error) {
						elements, err := node.parseData(valueArr, rel)
						for _, element := range elements {
							elObject.data = append(elObject.data, element)
						}
					}, "oneOf")
				} else {
					elements, _ := node.parseData(valueElement, rel)
					elObject.data = elements
				}
				elData.element = append(elData.element, elObject)
			}, "properties")
			if err != nil {
				return retData, xerrors.Errorf("Cannot parse JSON at object: %w", err)
			}
			retData = append(retData, elData)
			return retData, nil

		//type array
		case typeProp == "array":
			var elData Array
			elData.itemSize, _ = jsonparser.GetInt(json, "itemSize")
			elData.maxItems, _ = jsonparser.GetInt(json, "maxItems")
			elData.minItems, _ = jsonparser.GetInt(json, "minItems")
			valueItem, _, _, err := jsonparser.Get(json, "items")
			_, _, _, err = jsonparser.Get(valueItem, "oneOf")
			if err == nil {
				_, err = jsonparser.ArrayEach(valueItem, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
					items, _ := node.parseData(valueArray, rel)
					for _, item := range items {
						elData.data = append(elData.data, item)
					}
				}, "oneOf")
			} else {
				items, _ := node.parseData(valueItem, rel)
				for _, item := range items {
					elData.data = append(elData.data, item)
				}
			}
			retData = append(retData, elData)
			return retData, nil

		//type bitmap
		case typeProp == "bitmap":
			var elData Bitmap
			elData.size, _ = jsonparser.GetInt(json, "size")
			_, err = jsonparser.ArrayEach(json, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
				var elBitmap ElBitmap
				elBitmap.name, _ = jsonparser.GetString(valueArray, "name")
				elBitmap.descriptions, _ = jsonparser.GetString(valueArray, "descriptions", "en")
				elBitmap.index, _ = jsonparser.GetInt(valueArray, "position", "index")
				bitMask, _ := jsonparser.GetString(valueArray, "position", "bitMask")
				intBitMask, _ := strconv.ParseInt(bitMask, 0, 64)
				elBitmap.bitmask = uint64(intBitMask)
				value, _, _, _ := jsonparser.Get(valueArray, "value")
				vs, _ := node.parseData(value, rel)
				for _, v := range vs {
					elBitmap.value = append(elBitmap.value, v)
				}
				elData.bitmaps = append(elData.bitmaps, elBitmap)
			}, "bitmaps")

			if err != nil {
				node.logger.Error("Parse JSON ERROR in bitmap")
				return nil, xerrors.Errorf("Parse JSON ERROR in bitmap")
			}

			retData = append(retData, elData)
			return retData, nil

		//type numericValue
		case typeProp == "numericValue":
			var elData NumericValues
			elData.size, _ = jsonparser.GetInt(json, "size")
			_, err = jsonparser.ArrayEach(json, func(valueArray []byte, dataType jsonparser.ValueType, offset int, err error) {
				var e NumericValue

				edt, _ := jsonparser.GetString(valueArray, "edt")
				e.edt, _ = strconv.ParseInt(edt, 0, 64)
				e.value, _ = jsonparser.GetFloat(valueArray, "numericValue")
				elData.enum = append(elData.enum, e)
			}, "enum")

			if err != nil {
				node.logger.Error("Parse JSON ERROR in numericValue")
				return nil, xerrors.Errorf("Parse JSON ERROR in bitmap")
			}

			retData = append(retData, elData)
			return retData, nil

		//type time or date-time
		case typeProp == "time" || typeProp == "date-time":
			var elData DateTime
			elData.size, _ = jsonparser.GetInt(json, "size")
			retData = append(retData, elData)
			return retData, nil

		//key is ref or Invalid
		default:
			_, _, _, err := jsonparser.Get(json, "$ref")
			if err == nil {
				ref, err := jsonparser.GetString(json, "$ref")
				if err != nil {
					return retData, xerrors.Errorf("Invalid object of $ref: %w", err)
				}
				pathDef := ref[len("#/definitions/"):]
				valueData, _, _, err := jsonparser.Get(definition, pathDef)
				if err != nil {
					return retData, xerrors.Errorf("Invalid path %s: %w", pathDef, err)
				}
				elDatas, err := node.parseData(valueData, rel)
				if strings.HasPrefix(pathDef, "number") {
					unit, err := jsonparser.GetString(json, "unit")
					if err == nil {
						if value, ok := elDatas[len(elDatas)-1].(Number); ok {
							value.unit = unit
							elDatas[len(elDatas)-1] = value
						}
					}
					multi, err := jsonparser.GetFloat(json, "multipleOf")
					if err == nil {
						if value, ok := elDatas[len(elDatas)-1].(Number); ok {
							value.multipleOf = multi
							elDatas[len(elDatas)-1] = value
						}
					}
					_, _, _, err = jsonparser.Get(json, "coefficient")
					if err == nil {
						if value, ok := elDatas[len(elDatas)-1].(Number); ok {
							if err == nil {
								enums, _, _, _ := jsonparser.Get(json, "coefficient")
								var buf []byte
								for i := 0; ; i++ {
									if enums[i] == ',' || enums[i] == ']' {
										atoi, _ := strconv.Atoi(string(buf))
										value.coeff = append(value.coeff, uint8(atoi))
										buf = nil
										if enums[i] == ']' {
											break
										}

									} else if enums[i] != '[' {
										buf = append(buf, enums[i])
									}
								}
							}
						}
					}
				}
				if err != nil {
					return retData, xerrors.Errorf("Cannot parse data: %w", err)
				}
				for _, elData := range elDatas {
					retData = append(retData, elData)
				}
				return retData, err
			} else {
				return retData, xerrors.Errorf("InvalidKey %s", typeProp)
			}
		}
	}
}

func (node *Node) parseMetaData(json []byte, epc string) (Property, error) {
	var retProp Property
	var err error

	retProp.PropertyName, err = jsonparser.GetString(json, "propertyName", "en")
	if err != nil {
		return retProp, xerrors.Errorf("Failed to getinfo \"propertyName\" of json at %s:%w", epc, err)
	}

	retProp.Get, err = jsonparser.GetString(json, "accessRule", "get")
	if err != nil {
		return retProp, xerrors.Errorf("Failed to getinfo \"GET\" of json at %s:%w", epc, err)
	}

	retProp.Set, err = jsonparser.GetString(json, "accessRule", "set")
	if err != nil {
		return retProp, xerrors.Errorf("Failed to getinfo \"SET\" of json at %s:%w", epc, err)
	}

	retProp.Inf, err = jsonparser.GetString(json, "accessRule", "inf")
	if err != nil {
		return retProp, xerrors.Errorf("Failed to getinfo \"INF\" of json at %s:%w", epc, err)
	}

	retProp.Note, err = jsonparser.GetString(json, "note", "en")
	return retProp, nil
}
