package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brocaar/chirpstack-simulator/simulator"
	"github.com/brocaar/lorawan"
	"github.com/chirpstack/chirpstack/api/go/v4/gw"
	log "github.com/sirupsen/logrus"
)

// This script simulates a side channel attack on LoRaWAN. It comprises the OTAA activation of 2 end devices, a sender and a receiver.
// The sender sends of a series of uplink frames encoding a hidden message, the receiver receiver sniff the downlinks,
//  decode the secret and the simulation terminates. The scenario is as follows:
// 1. A message is chosen, for example the 128 bit Application key of the sender.
// 2. The message is encoded with 3 different modes:
//    . in pairs of bits, where each pair is mapped to an integer, if the encoding uses MAC Commands or Spreading Factor technique:
//    	- "00" -> 1/5 (MAC Commands/Spreading Factor)
//    	- "01" -> 2/6 (MAC Commands/Spreading Factor)
//    	- "10" -> 3/7 (MAC Commands/Spreading Factor)
//    	- "11" -> 4/8 (MAC Commands/Spreading Factor)
//    . in quadruplets of bits, where each quadruplet is mapped to two integers, if the encoding uses MAC Commands and
// 		Spreading Factor techniques combined. This results in 16 possible combinations, each of them mapped to a pair of integers:
//    	- "0000" -> [1, 5]
//    	- "0001" -> [1, 6]
//    	- "0010" -> [1, 7]
//    	- "0011" -> [1, 8]
//    	- "0100" -> [2, 5]
//    	- "0101" -> [2, 6]
//    	- "0110" -> [2, 7]
//    	- "0111" -> [2, 8]
//    	- "1000" -> [3, 5]
//    	- "1001" -> [3, 6]
//    	- "1010" -> [3, 7]
//    	- "1011" -> [3, 8]
//    	- "1100" -> [4, 5]
//    	- "1101" -> [4, 6]
//    	- "1110" -> [4, 7]
//    	- "1111" -> [4, 8]
// 3. The sender sends a series of uplink messages, each of them containing one of the different combinations of the mappings.
// 4. A second device receives these uplink messages and decodes the integers back into pairs of bits.
// 5. The pairs of bits are then concatenated to reconstruct the original binary string.
// 6. Finally, the binary string is split into bytes, which are then converted to a UTF-8 string, revealing the secret message.

// ************************ UTILITY VARIABLES ************************
const MAC_COMMANDS_ENCODING = true // This variable is used to indicate whether the encoding use MAC Commands or not.
const SF_ENCODING = true           // This variable is used to indicate whether the encoding uses Spreading Factor or not.
var number_of_headers int = 0      // This variable is used to count the number of headers sent in the uplink messages.

// ************************ UTILITY FUNCTIONS ************************

// BytesToBinaryString converte una slice di byte in una stringa binaria.
// Ogni byte è rappresentato con 8 caratteri ('0' o '1'), MSB first.
func BytesToBinaryString(data []byte) string {
	var sb strings.Builder
	sb.Grow(len(data) * 8) // facciamo il Grow per evitare riallocazioni

	for _, b := range data {
		// scorro da 7 a 0 per prendere i bit dal più significativo al meno
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
	}

	return sb.String()
}

// BinaryStringToBytes converte una stringa binaria (es. "10101011…")
// in una slice di byte. La stringa deve avere lunghezza multipla di 8.
func BinaryStringToBytes(s string) ([]byte, error) {
	if len(s)%8 != 0 {
		return nil, errors.New("la lunghezza della stringa deve essere un multiplo di 8")
	}

	n := len(s) / 8
	out := make([]byte, n)

	for i := 0; i < n; i++ {
		byteStr := s[i*8 : (i+1)*8]
		// Parse della sottostringa binaria in un numero da 0 a 255
		val, err := strconv.ParseUint(byteStr, 2, 8)
		if err != nil {
			return nil, fmt.Errorf("errore nel parsing del byte %d (%q): %w", i, byteStr, err)
		}
		out[i] = byte(val)
	}

	return out, nil
}

// splitIntoPairs takes a binary string and splits it into pairs of bits.
func splitIntoPairs(binaryStr string) []string {
	var pairs []string
	for i := 0; i < len(binaryStr)-1; i += 2 {
		pair := binaryStr[i : i+2]
		pairs = append(pairs, pair)
	}
	return pairs
}

// mapPairsToInts maps pairs of bits to integers:
// "00" -> 1, "01" -> 2, "10" -> 3, "11" -> 4.
func mapPairsToInts(pairs []string) [][]byte {
	var output [][]byte
	if MAC_COMMANDS_ENCODING && SF_ENCODING {
		output = make([][]byte, 0, (len(pairs)/2)+2) // +2 to account for the start and the end of the message markers
		output = append(output, []byte{0, 0})        // Append a 0 to the start of the encoded secret to indicate the start of the message
	} else if (MAC_COMMANDS_ENCODING && !SF_ENCODING) || (!MAC_COMMANDS_ENCODING && SF_ENCODING) {
		output = make([][]byte, 0, len(pairs)+2) // +2 to account for the start and the end of the message markers
		output = append(output, []byte{0})       // Append a 0 to the start of the encoded secret to indicate the start of the message
	}

	if MAC_COMMANDS_ENCODING && !SF_ENCODING {
		for _, p := range pairs {
			switch p {
			case "00":
				output = append(output, []byte{1})
			case "01":
				output = append(output, []byte{2})
			case "10":
				output = append(output, []byte{3})
			case "11":
				output = append(output, []byte{4})
			}
		}
	} else if MAC_COMMANDS_ENCODING && SF_ENCODING {
		var output_index int = 1 // Start from 1 because the first element is reserved for the start marker
		for i := 0; i+1 < len(pairs); i += 2 {
			switch pairs[i] {
			case "00":
				output = append(output, []byte{1})
			case "01":
				output = append(output, []byte{2})
			case "10":
				output = append(output, []byte{3})
			case "11":
				output = append(output, []byte{4})

			}

			switch pairs[i+1] {
			case "00":
				output[output_index] = append(output[output_index], 5)
			case "01":
				output[output_index] = append(output[output_index], 6)
			case "10":
				output[output_index] = append(output[output_index], 7)
			case "11":
				output[output_index] = append(output[output_index], 8)
			}

			output_index++
		}
	} else if !MAC_COMMANDS_ENCODING && SF_ENCODING {
		for _, p := range pairs {
			switch p {
			case "00":
				output = append(output, []byte{5})
			case "01":
				output = append(output, []byte{6})
			case "10":
				output = append(output, []byte{7})
			case "11":
				output = append(output, []byte{8})
			}
		}

	}

	if MAC_COMMANDS_ENCODING && SF_ENCODING {
		output = append(output, []byte{0, 0}) // Append a 0 to the end of the encoded secret to indicate the end of the message
	} else if (MAC_COMMANDS_ENCODING && !SF_ENCODING) || (!MAC_COMMANDS_ENCODING && SF_ENCODING) {
		output = append(output, []byte{0}) // Append a 0 to the end of the encoded secret to indicate the end of the message
	}

	return output
}

// byteToBinary takes a byte and returns its binary representation as a string of 8 bits.
func byteToBinary(b byte) string {
	return fmt.Sprintf("%08b", b)
}

// fourBitsToInt converts a string of 4 bits to an integer.
// It uses strconv.ParseUint to parse the string as a base-2 number with a maximum bit size of 4.
func fourBitsToInt(s string) (int, error) {
	// ParseUint takes a string, base (2 for binary), and bit size (4 bits max).
	v, err := strconv.ParseUint(s, 2, 4)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// joinPairs concatenates pairs of bits into a single binary string.
// It assumes that the input is a slice of strings, each string being a pair of bits (length 2).
func joinPairs(pairs []string) string {
	var b strings.Builder
	for _, p := range pairs {
		if len(p) != 2 {
			continue
		}
		b.WriteString(p)
	}
	return b.String()
}

func main() {
	//**********************************
	fmt.Println("INIZIO")
	//**********************************

	// We define the gateway ID, device EUI, and application key for both devices.
	// One will be used to send the uplink messages, while the other will be used to receive the downlink messages.
	// These values are used to simulate the devices and gateway on the ChirpStack server.
	gatewayID := lorawan.EUI64{86, 129, 144, 230, 90, 144, 139, 200}
	devEUI := lorawan.EUI64{35, 171, 118, 58, 232, 88, 238, 14}
	appKey := lorawan.AES128Key{69, 244, 243, 66, 203, 176, 131, 63, 52, 254, 228, 107, 222, 22, 121, 235}
	devEUI_2 := lorawan.EUI64{46, 151, 2, 172, 7, 195, 79, 89}
	appKey_2 := lorawan.AES128Key{77, 59, 215, 197, 59, 181, 18, 136, 196, 83, 215, 185, 153, 121, 26, 116}

	var wg sync.WaitGroup
	ctx := context.Background()

	// Here we define the secret message (in this case the AppKey) and convert it to binary, then split it into pairs of bits
	// and map those pairs to integers.
	var temp, err = appKey.MarshalText()
	if err != nil {
		panic(err)
	}
	fmt.Println("Secret message to exfiltrate:", string(temp))

	temp, err = appKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	var secret_message []byte = temp //128 bit total, 16 bytes
	fmt.Println("Secret message:", temp)

	var secret_message_binary string = BytesToBinaryString(secret_message) // Convert the byte slice to a binary string
	fmt.Println("Secret message in binary:", secret_message_binary)
	fmt.Println("Length of secret_message_binary: ", len(secret_message_binary))

	var pairs_of_bits []string = splitIntoPairs(secret_message_binary)
	fmt.Println("secret message in pairs of bits:", pairs_of_bits)
	fmt.Println("Length of pairs_of_bits: ", len(pairs_of_bits))

	var encoded_secret [][]byte = mapPairsToInts(pairs_of_bits)
	fmt.Println("encoded_secret: ", encoded_secret)
	fmt.Println("encoded_secret len: ", len(encoded_secret))

	// Here will be stored the received encoded secret from the downlink messages
	// We initialize it with a capacity equal to the length of the encoded_secret
	var received_encoded_secret []string = make([]string, 0, len(encoded_secret))

	// We can set the uplink interval to an aribtrary amount of time (in this case 2 seconds),
	// which is the time between uplink messages
	var uplinkInterval int = 1

	// We create a new gateway with the given ID.
	sgw, err := simulator.NewGateway(
		simulator.WithMQTTCredentials("localhost:1883", "", ""),
		simulator.WithGatewayID(gatewayID),
		simulator.WithEventTopicTemplate("eu868/gateway/{{ .GatewayID }}/event/{{ .Event }}"),
		simulator.WithCommandTopicTemplate("eu868/gateway/{{ .GatewayID }}/command/{{ .Command }}"),
	)
	if err != nil {
		panic(err)
	}

	startNow := time.Now()

	// Then we create a new device with the given DevEUI and AppKey that will send uplink messages.
	_, err = simulator.NewDevice(ctx, &wg,
		simulator.WithDevEUI(devEUI),
		simulator.WithAppKey(appKey),
		simulator.WithRandomDevNonce(),
		simulator.WithUplinkInterval(time.Duration(uplinkInterval)*time.Second),
		simulator.WithUplinkCount(uint32(len(encoded_secret))),
		simulator.WithUplinkPayload(true, 10, []byte{}), //simulator.WithUplinkPayload(true, 10, []byte{1, 2, 3}),
		simulator.WithSecretToExfiltrate(encoded_secret),
		simulator.WithUplinkTXInfo(gw.UplinkTxInfo{
			Frequency: 868100000,
			Modulation: &gw.Modulation{
				Parameters: &gw.Modulation_Lora{
					Lora: &gw.LoraModulationInfo{
						Bandwidth:       125000,
						SpreadingFactor: 7,
						CodeRate:        gw.CodeRate_CR_4_5,
					},
				},
			},
		}),
		simulator.WithGateways([]*simulator.Gateway{sgw}),
		simulator.WithDownlinkHandlerFunc(func(conf, ack bool, fCntDown uint32, fPort uint8, data []byte, fctrl []byte, spreading_factor uint32) error {
			log.WithFields(log.Fields{
				"ack":       ack,
				"fcnt_down": fCntDown,
				"f_port":    fPort,
				"data":      hex.EncodeToString(data),
			}).Info("WithDownlinkHandlerFunc triggered")

			return nil
		}),
	)

	if err != nil {
		panic(err)
	}

	// We create a second device with the given DevEUI and AppKey that will receive downlink messages.
	_, err = simulator.NewDevice(ctx, &wg,
		simulator.WithDevEUI(devEUI_2),
		simulator.WithAppKey(appKey_2),
		simulator.WithRandomDevNonce(),
		simulator.WithUplinkInterval(time.Duration(uplinkInterval)*time.Second),
		simulator.WithUplinkCount(uint32(len(encoded_secret))),
		simulator.WithUplinkPayload(true, 10, []byte{}),
		simulator.WithUplinkTXInfo(gw.UplinkTxInfo{
			Frequency: 868100000,
			Modulation: &gw.Modulation{
				Parameters: &gw.Modulation_Lora{
					Lora: &gw.LoraModulationInfo{
						Bandwidth:       125000,
						SpreadingFactor: 7,
						CodeRate:        gw.CodeRate_CR_4_5,
					},
				},
			},
		}),
		simulator.WithGateways([]*simulator.Gateway{sgw}),
		simulator.WithDownlinkHandlerFunc(func(conf, ack bool, fCntDown uint32, fPort uint8, data []byte, fctrl []byte, spreading_factor uint32) error {
			log.WithFields(log.Fields{
				"ack":       ack,
				"fcnt_down": fCntDown,
				"f_port":    fPort,
				"data":      hex.EncodeToString(data),
			}).Info("WithDownlinkHandlerFunc triggered")

			// Here we process the received downlink message.
			// We access the FCtrl byte to determine the length of the FOpts field (FOptsLen),
			// transform it into an integer value and then map it to the corresponding encoded secret value
			// to reconstruct the original secret message.

			if spreading_factor == 12 {
				number_of_headers++
			}

			if fPort == 0 && (spreading_factor == 7 || spreading_factor == 8 || spreading_factor == 9 || spreading_factor == 10) {
				var temp string = byteToBinary(fctrl[0])
				var fOptsLenBits = temp[len(temp)-4 : len(temp)]
				var fOptsLen, err = fourBitsToInt(fOptsLenBits)
				if err != nil {
					log.WithError(err).Error("Error converting fOptsLenBits to int")
					return err
				}

				if MAC_COMMANDS_ENCODING {
					switch fOptsLen {
					case 0:
						received_encoded_secret = append(received_encoded_secret, "00")
					case 3:
						received_encoded_secret = append(received_encoded_secret, "01")
					case 6:
						received_encoded_secret = append(received_encoded_secret, "10")
					case 9:
						received_encoded_secret = append(received_encoded_secret, "11")
					}
				}

				if SF_ENCODING {
					switch spreading_factor {
					case 7:
						received_encoded_secret = append(received_encoded_secret, "00")
					case 8:
						received_encoded_secret = append(received_encoded_secret, "01")
					case 9:
						received_encoded_secret = append(received_encoded_secret, "10")
					case 10:
						received_encoded_secret = append(received_encoded_secret, "11")
					}
				}

				fmt.Println("received_encoded_secret: ", received_encoded_secret)
				fmt.Println("received_encoded_secret len: ", len(received_encoded_secret))
			}

			// Once all the pairs have been received, the secret message can be reconstructed.
			if spreading_factor == 12 && number_of_headers == 2 {
				var decoded_secret_binary string = joinPairs(received_encoded_secret)
				fmt.Println("decoded_secret: ", decoded_secret_binary)
				var decoded_secret, err = BinaryStringToBytes(decoded_secret_binary)
				if err != nil {
					log.WithError(err).Error("Error converting decoded_secret to bytes")
					return err
				}
				var temp lorawan.AES128Key
				if err := temp.UnmarshalBinary(decoded_secret); err != nil {
					log.WithError(err).Error("Error unmarshalling decoded_secret to AES128Key")
					return err
				}
				temp2, err := temp.MarshalText()
				if err != nil {
					log.WithError(err).Error("Error marshalling decoded_secret to text")
					return err
				}
				var received_secret string = string(temp2)
				/* byte_formatted_secret := splitIntoBytes(decoded_secret)
				fmt.Println("byteFormattedSecret: ", byte_formatted_secret)
				decoded_string, err := bytesToString(byte_formatted_secret)
				if err != nil {
					log.WithError(err).Error("Error converting byteFormattedSecret to string")
					return err
				} */
				fmt.Println("Received secret: ", received_secret)
				fmt.Println("Total time taken:", time.Since(startNow))
			}

			return nil
		}),
	)

	if err != nil {
		panic(err)
	}

	wg.Wait()
}
