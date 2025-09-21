package simulator

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/brocaar/lorawan"
	"github.com/chirpstack/chirpstack/api/go/v4/gw"
)

// DeviceOption is the interface for a device option.
type DeviceOption func(*Device) error

type deviceState int

const (
	deviceStateOTAA deviceState = iota
	deviceStateActivated
	deviceStateActivatedRDONLY
)

// Device contains the state of a simulated LoRaWAN OTAA device (1.0.x).
type Device struct {
	sync.RWMutex

	// Context to cancel device.
	ctx context.Context

	// Cancel function.
	cancel context.CancelFunc

	// Waitgroup to wait until simulation has been fully cancelled.
	wg *sync.WaitGroup

	// DevEUI.
	devEUI lorawan.EUI64

	// JoinEUI.
	joinEUI lorawan.EUI64

	// AppKey.
	appKey lorawan.AES128Key

	// Interval in which device sends uplinks.
	uplinkInterval time.Duration

	// Total number of uplinks to send, before terminating.
	uplinkCount uint32

	// Device sends uplink as confirmed.
	confirmed bool

	// Payload (plaintext) which the device sends as uplink.
	payload []byte

	// FPort used for sending uplinks.
	fPort uint8

	// Options for MAC commands.
	fOpts []lorawan.Payload

	// Assigned device address.
	devAddr lorawan.DevAddr

	// DevNonce.
	devNonce lorawan.DevNonce

	// Uplink frame-counter.
	fCntUp uint32

	// Downlink frame-counter.
	fCntDown uint32

	// Application session-key.
	appSKey lorawan.AES128Key

	// Network session-key.
	nwkSKey lorawan.AES128Key

	// Activation state.
	state deviceState

	// Downlink frames channel (used by the gateway). Note that the gateway
	// forwards downlink frames to all associated devices, as only the device
	// is able to validate the addressee.
	downlinkFrames chan gw.DownlinkFrame

	// The associated gateway through which the device simulates its uplinks.
	gateways []*Gateway

	// Random DevNonce
	randomDevNonce bool

	// TXInfo for uplink
	uplinkTXInfo gw.UplinkTxInfo

	// Downlink handler function.
	downlinkHandlerFunc func(confirmed, ack bool, fCntDown uint32, fPort uint8, data []byte, fctrl []byte, spreading_factor uint32) error

	// OTAA delay.
	otaaDelay time.Duration

	//Number of downlink frames received
	downlinkFramesReceived uint32

	// Indicates if the uplink contains a header for the encoded secret message.
	// Used to indicate the preamble and postamble so that the receiver can
	// decode secret messages with arbitrary length
	isHeader bool

	// Secret to exfiltrate
	secret [][]byte
}

// WithAppKey sets the AppKey.
func WithAppKey(appKey lorawan.AES128Key) DeviceOption {
	return func(d *Device) error {
		d.appKey = appKey
		return nil
	}
}

// WithDevEUI sets the DevEUI.
func WithDevEUI(devEUI lorawan.EUI64) DeviceOption {
	return func(d *Device) error {
		d.devEUI = devEUI
		return nil
	}
}

// WithJoinEUI sets the JoinEUI.
func WithJoinEUI(joinEUI lorawan.EUI64) DeviceOption {
	return func(d *Device) error {
		d.joinEUI = joinEUI
		return nil
	}
}

// WithOTAADelay sets the OTAA delay.
func WithOTAADelay(delay time.Duration) DeviceOption {
	return func(d *Device) error {
		d.otaaDelay = delay
		return nil
	}
}

// WithUplinkInterval sets the uplink interval.
func WithUplinkInterval(interval time.Duration) DeviceOption {
	return func(d *Device) error {
		d.uplinkInterval = interval
		return nil
	}
}

// WithUplinkCount sets the uplink count, after which the device simulation
// ends.
func WithUplinkCount(count uint32) DeviceOption {
	return func(d *Device) error {
		d.uplinkCount = count
		return nil
	}
}

// WithUplinkPayload sets the uplink payload.
func WithUplinkPayload(confirmed bool, fPort uint8, pl []byte) DeviceOption {
	return func(d *Device) error {
		d.fPort = fPort
		d.payload = pl
		d.confirmed = confirmed
		return nil
	}
}

// WithFOpts sets the uplink fopts.
func WithFOpts(fOpts []lorawan.Payload) DeviceOption {
	//fmt.Println("Sto per printare fOpts")
	//fmt.Println(fOpts)
	//fmt.Println("Sto per aggiornare d.fOpts")
	return func(d *Device) error {
		d.fOpts = make([]lorawan.Payload, len(fOpts))
		copy(d.fOpts, fOpts)
		return nil
	}
}

// WithGateways adds the device to the given gateways.
// Use this function after WithDevEUI!
func WithGateways(gws []*Gateway) DeviceOption {
	return func(d *Device) error {
		d.gateways = gws

		for i := range d.gateways {
			d.gateways[i].addDevice(d.devEUI, d.downlinkFrames)
		}
		return nil
	}
}

// WithRandomDevNonce randomizes the OTAA DevNonce instead of using a counter value.
func WithRandomDevNonce() DeviceOption {
	return func(d *Device) error {
		d.randomDevNonce = true
		return nil
	}
}

// WithUplinkTXInfo sets the TXInfo used for simulating the uplinks.
func WithUplinkTXInfo(txInfo gw.UplinkTxInfo) DeviceOption {
	return func(d *Device) error {
		d.uplinkTXInfo = txInfo
		return nil
	}
}

// WithDownlinkHandlerFunc sets the downlink handler func.
func WithDownlinkHandlerFunc(f func(confirmed, ack bool, fCntDown uint32, fPort uint8, data []byte, fctrl []byte, spreading_factor uint32) error) DeviceOption {
	return func(d *Device) error {
		d.downlinkHandlerFunc = f
		return nil
	}
}

func WithSecretToExfiltrate(secret [][]byte) DeviceOption {
	return func(d *Device) error {
		// This option is used to set the secret to exfiltrate, which is not
		// directly related to the device definition but is used in the
		// simulation to encode the secret in the uplink payload.
		d.secret = secret
		return nil
	}

}

// NewDevice creates a new device simulation.
func NewDevice(ctx context.Context, wg *sync.WaitGroup, opts ...DeviceOption) (*Device, error) {
	ctx, cancel := context.WithCancel(ctx)

	d := &Device{
		ctx:    ctx,
		cancel: cancel,
		wg:     wg,

		downlinkFrames: make(chan gw.DownlinkFrame, 100),
		state:          deviceStateOTAA,
	}

	for _, o := range opts {
		if err := o(d); err != nil {
			return nil, err
		}
	}

	log.WithFields(log.Fields{
		"dev_eui": d.devEUI,
	}).Info("simulator: new otaa device")

	wg.Add(2)

	go d.uplinkLoop()
	go d.downlinkLoop()

	return d, nil
}

// uplinkLoop first handle the OTAA activation, after which it will periodically
// sends an uplink with the configured payload and fport.
func (d *Device) uplinkLoop() {
	defer d.cancel()
	defer d.wg.Done()

	var cancelled bool
	go func() {
		<-d.ctx.Done()
		cancelled = true
	}()

	time.Sleep(d.otaaDelay)

	for !cancelled {
		switch d.getState() {
		case deviceStateOTAA:
			//fmt.Println("Sto per inviare una JoinRequest")
			d.joinRequest()
			time.Sleep(6 * time.Second)
		case deviceStateActivated:
			/* fmt.Println("Sto per inviare una dataUp")
			fmt.Println("Sto per printare d.fCntUp")
			fmt.Println(d.fCntUp) */

			d.dataUp()

			if d.fCntUp >= d.uplinkCount {
				// d.cancel() also cancels the downlink loop. Wait one
				// second in order to process any potential downlink
				// response (e.g. and ack).
				time.Sleep(time.Second)
				fmt.Println("Sto per invocare d.cancel() e questo è il devEUI:", d.devEUI)
				d.cancel()
				return
			}
			toa := d.computePacketTOA()
			fmt.Println("Time on Air:", toa, "devEUI:", d.devEUI)
			wait_time := time.Duration(toa * 99)
			fmt.Println("Uplink interval:", wait_time, "devEUI:", d.devEUI)
			time.Sleep(wait_time)

		case deviceStateActivatedRDONLY:
			fmt.Println("busy waiting for downlink")
			time.Sleep(time.Second * 2)
			//fmt.Println("d.downlinkFramesReceived", d.downlinkFramesReceived)
			//fmt.Println("d.uplinkCount", d.uplinkCount)
			//fmt.Println("d.downlinkFramesReceived >= int(d.uplinkCount)", d.downlinkFramesReceived >= int(d.uplinkCount))

			if d.downlinkFramesReceived >= d.uplinkCount {
				//fmt.Println("sto per invocare d.cancel()")
				d.cancel()
				return

			}
		}
	}
}

// downlinkLoop handles the downlink messages.
// Note: as a gateway does not know the addressee of the downlink, it is up to
// the handling functions to validate the MIC etc..
func (d *Device) downlinkLoop() {
	defer d.cancel()
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return

		case pl := <-d.downlinkFrames:
			for _, item := range pl.Items {
				err := func() error {

					var sf_dl uint32 = item.TxInfo.Modulation.GetLora().SpreadingFactor
					//fmt.Println("Spreading Factor downlink:", sf_dl, "devEUI:", d.devEUI)

					var phy lorawan.PHYPayload

					if err := phy.UnmarshalBinary(item.PhyPayload); err != nil {
						return errors.Wrap(err, "unmarshal phypayload error")
					}

					switch phy.MHDR.MType {
					case lorawan.JoinAccept:
						return d.joinAccept(phy)
					case lorawan.UnconfirmedDataDown, lorawan.ConfirmedDataDown:
						/* if d.devEUI == (lorawan.EUI64{46, 151, 2, 172, 7, 195, 79, 89}) {
							item.TxInfo.Modulation.Parameters.
						} */
						//fmt.Println("sto per invocare la downlinkData e questo è il devEUI", d.devEUI)
						return d.downlinkData(phy, sf_dl)
					}

					return nil
				}()

				if err != nil {
					log.WithError(err).Error("simulator: handle downlink frame error")
				}

				break
			}
		}
	}
}

// joinRequest sends the join-request.
func (d *Device) joinRequest() {
	log.WithFields(log.Fields{
		"dev_eui": d.devEUI,
	}).Debug("simulator: send OTAA request")

	phy := lorawan.PHYPayload{
		MHDR: lorawan.MHDR{
			MType: lorawan.JoinRequest,
			Major: lorawan.LoRaWANR1,
		},
		MACPayload: &lorawan.JoinRequestPayload{
			DevEUI:   d.devEUI,
			JoinEUI:  d.joinEUI,
			DevNonce: d.getDevNonce(),
		},
	}

	if err := phy.SetUplinkJoinMIC(d.appKey); err != nil {
		log.WithError(err).Error("simulator: set uplink join mic error")
		return
	}

	d.sendUplink(phy)

	deviceJoinRequestCounter().Inc()
}

// dataUp sends an data uplink.
func (d *Device) dataUp() {
	log.WithFields(log.Fields{
		"dev_eui":   d.devEUI,
		"dev_addr":  d.devAddr,
		"confirmed": d.confirmed,
	}).Debug("simulator: send uplink data")

	mType := lorawan.UnconfirmedDataUp
	if d.confirmed {
		mType = lorawan.ConfirmedDataUp
	}

	if d.secret != nil && len(d.secret) > 0 && d.secret[0][0] < 5 && int(d.fCntUp) < len(d.secret) {
		if d.secret[d.fCntUp][0] == 0 {
			d.fOpts = []lorawan.Payload{}
			d.isHeader = true // Indicate that this uplink contains a header for the encoded secret message
		} else if d.secret[d.fCntUp][0] == 1 {
			d.fOpts = []lorawan.Payload{}
		} else if d.secret[d.fCntUp][0] == 2 {
			d.fOpts = []lorawan.Payload{
				&lorawan.MACCommand{
					CID: lorawan.LinkCheckReq,
				},
			}
		} else if d.secret[d.fCntUp][0] == 3 {
			d.fOpts = []lorawan.Payload{
				&lorawan.MACCommand{
					CID: lorawan.DeviceTimeReq,
				},
			}
		} else if d.secret[d.fCntUp][0] == 4 {
			d.fOpts = []lorawan.Payload{
				&lorawan.MACCommand{
					CID: lorawan.LinkCheckReq,
				},
				&lorawan.MACCommand{
					CID: lorawan.DeviceTimeReq,
				},
			}
		}
	}

	phy := lorawan.PHYPayload{
		MHDR: lorawan.MHDR{
			MType: mType,
			Major: lorawan.LoRaWANR1,
		},
		MACPayload: &lorawan.MACPayload{
			FHDR: lorawan.FHDR{
				DevAddr: d.devAddr,
				FCnt:    d.fCntUp,
				FOpts:   d.fOpts, // Here we can add MAC commands
				FCtrl: lorawan.FCtrl{
					ADR: false,
				},
			},
			FPort: &d.fPort,
			FRMPayload: []lorawan.Payload{
				&lorawan.DataPayload{
					Bytes: d.payload,
				},
			},
		},
	}

	if err := phy.EncryptFRMPayload(d.appSKey); err != nil {
		log.WithError(err).Error("simulator: encrypt FRMPayload error")
		return
	}

	if err := phy.SetUplinkDataMIC(lorawan.LoRaWAN1_0, 0, 0, 0, d.nwkSKey, d.nwkSKey); err != nil {
		log.WithError(err).Error("simulator: set uplink data mic error")
		return
	}

	d.fCntUp++

	d.sendUplink(phy)

	deviceUplinkCounter().Inc()
}

// joinAccept validates and handles the join-accept downlink.
func (d *Device) joinAccept(phy lorawan.PHYPayload) error {
	err := phy.DecryptJoinAcceptPayload(d.appKey)
	if err != nil {
		return errors.Wrap(err, "decrypt join-accept payload error")
	}

	ok, err := phy.ValidateDownlinkJoinMIC(lorawan.JoinRequestType, d.joinEUI, d.devNonce, d.appKey)
	if err != nil {
		log.WithFields(log.Fields{
			"dev_eui": d.devEUI,
		}).Debug("simulator: invalid join-accept MIC")
		return nil
	}
	if !ok {
		log.WithFields(log.Fields{
			"dev_eui": d.devEUI,
		}).Debug("simulator: invalid join-accept MIC")
		return nil
	}

	jaPL, ok := phy.MACPayload.(*lorawan.JoinAcceptPayload)
	if !ok {
		return errors.New("expected *lorawan.JoinAcceptPayload")
	}

	d.appSKey, err = getAppSKey(jaPL.DLSettings.OptNeg, d.appKey, jaPL.HomeNetID, d.joinEUI, jaPL.JoinNonce, d.devNonce)
	if err != nil {
		return errors.Wrap(err, "get AppSKey error")
	}

	d.nwkSKey, err = getFNwkSIntKey(jaPL.DLSettings.OptNeg, d.appKey, jaPL.HomeNetID, d.joinEUI, jaPL.JoinNonce, d.devNonce)
	if err != nil {
		return errors.Wrap(err, "get NwkSKey error")
	}

	d.devAddr = jaPL.DevAddr

	log.WithFields(log.Fields{
		"dev_eui":  d.devEUI,
		"dev_addr": d.devAddr,
	}).Info("simulator: device OTAA activated")

	if d.devEUI == (lorawan.EUI64{46, 151, 2, 172, 7, 195, 79, 89}) { //Added
		//Receiver device will only be able to receive downlink frames
		d.setState(deviceStateActivatedRDONLY)
	} else {
		d.setState(deviceStateActivated)
	}
	deviceJoinAcceptCounter().Inc()

	return nil
}

// downlinkData validates and handles the downlink data.
func (d *Device) downlinkData(phy lorawan.PHYPayload, spreading_factor uint32) error {
	//fmt.Println("Sto per validare il downlinkDataMIC e questo è il devEUI", d.devEUI)
	ok, err := phy.ValidateDownlinkDataMIC(lorawan.LoRaWAN1_0, 0, d.nwkSKey)
	//fmt.Println("Ho validato il downlinkDataMIC e questo è il devEUI", d.devEUI)
	if err != nil {
		fmt.Println("sto per loggare l'errore", d.devEUI)
		log.WithFields(log.Fields{
			"dev_eui": d.devEUI,
		}).Debug("simulator: invalid downlink data MIC")
		return nil
	}

	if d.devEUI != (lorawan.EUI64{46, 151, 2, 172, 7, 195, 79, 89}) {
		if !ok {
			fmt.Println("Non è ok", d.devEUI)
			log.WithFields(log.Fields{
				"dev_eui": d.devEUI,
			}).Debug("simulator: invalid downlink data MIC")
			return nil
		}
	}

	macPL, ok := phy.MACPayload.(*lorawan.MACPayload)
	if !ok {
		return fmt.Errorf("expected *lorawan.MACPayload, got: %T", phy.MACPayload)
	}

	gap := uint32(uint16(macPL.FHDR.FCnt) - uint16(d.fCntDown%(1<<16)))
	d.fCntDown = d.fCntDown + gap

	var data []byte
	var fPort uint8
	if macPL.FPort != nil {
		fPort = *macPL.FPort
	}

	if fPort != 0 {
		err := phy.DecryptFRMPayload(d.appSKey)
		if err != nil {
			return errors.Wrap(err, "decrypt frmpayload error")
		}

		if len(macPL.FRMPayload) != 0 {
			pl, ok := macPL.FRMPayload[0].(*lorawan.DataPayload)
			if !ok {
				return fmt.Errorf("expected *lorawan.DataPayload, got: %T", macPL.FRMPayload[0])
			}

			data = pl.Bytes
		}
	}

	log.WithFields(log.Fields{
		"confirmed": phy.MHDR.MType == lorawan.ConfirmedDataDown,
		"ack":       macPL.FHDR.FCtrl.ACK,
		"f_cnt":     d.fCntDown,
		"dev_eui":   d.devEUI,
		"f_port":    fPort,
		"data":      hex.EncodeToString(data),
	}).Info("simulator: device received downlink data")

	b, err := macPL.FHDR.FCtrl.MarshalBinary()

	if err != nil {
		return errors.Wrap(err, "marshal fctrl error")
	}

	//fmt.Println("Versione binaria di FCTRL", b, "con devEUI", d.devEUI)

	if d.downlinkHandlerFunc == nil {
		return nil
	}

	d.downlinkFramesReceived++
	return d.downlinkHandlerFunc(phy.MHDR.MType == lorawan.ConfirmedDataDown, macPL.FHDR.FCtrl.ACK, d.fCntDown, fPort, data, b, spreading_factor)
}

// sendUplink sends
func (d *Device) sendUplink(phy lorawan.PHYPayload) error {
	b, err := phy.MarshalBinary()

	if err != nil {
		return errors.Wrap(err, "marshal phypayload error")
	}

	pl := gw.UplinkFrame{
		PhyPayload: b,
		TxInfo:     &d.uplinkTXInfo,
	}

	//var sf_ul uint32 = pl.TxInfo.Modulation.GetLora().SpreadingFactor
	//fmt.Println("Spreading Factor uplink:", sf_ul, "devEUI:", d.devEUI)
	if d.isHeader {
		pl.TxInfo.Modulation.GetLora().SpreadingFactor = 12
	} else {
		if d.secret != nil && d.secret[0] != nil && len(d.secret[0]) == 1 && d.secret[1][0] < 5 {
			pl.TxInfo.Modulation.GetLora().SpreadingFactor = 7
		} else if d.secret != nil && d.secret[0] != nil && len(d.secret[0]) == 1 && d.fCntUp > 0 {
			switch d.secret[d.fCntUp-1][0] {
			case 5:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 7
			case 6:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 8
			case 7:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 9
			case 8:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 10
			}
		} else if d.secret != nil && d.secret[0] != nil && len(d.secret[0]) == 2 && d.fCntUp > 0 {
			switch d.secret[d.fCntUp-1][1] {
			case 5:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 7
			case 6:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 8
			case 7:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 9
			case 8:
				pl.TxInfo.Modulation.GetLora().SpreadingFactor = 10
			}
		}
	}
	//fmt.Println("Spreading Factor uplink:", pl.TxInfo.Modulation.GetLora().SpreadingFactor, "devEUI:", d.devEUI)

	for i := range d.gateways {
		if err := d.gateways[i].SendUplinkFrame(pl); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"dev_eui": d.devEUI,
			}).Error("simulator: send uplink frame error")
		}
	}

	d.isHeader = false // Reset header flag after sending uplink

	return nil
}

// getDevNonce increments and returns a LoRaWAN DevNonce.
func (d *Device) getDevNonce() lorawan.DevNonce {
	if d.randomDevNonce {
		b := make([]byte, 2)
		_, _ = crand.Read(b)

		d.devNonce = lorawan.DevNonce(binary.BigEndian.Uint16(b))
	} else {
		d.devNonce++
	}

	return d.devNonce
}

// getState returns the current device state.
func (d *Device) getState() deviceState {
	d.RLock()
	defer d.RUnlock()

	return d.state
}

// setState sets the device to the given state.
func (d *Device) setState(s deviceState) {
	d.Lock()
	d.Unlock()

	d.state = s
}

// computePacketTOA computes the packet Time On Air (TOA)
func (d *Device) computePacketTOA() time.Duration {
	sf := float64(d.uplinkTXInfo.Modulation.GetLora().SpreadingFactor)
	bandwidth := float64(d.uplinkTXInfo.Modulation.GetLora().Bandwidth)
	cr := float64(d.uplinkTXInfo.Modulation.GetLora().CodeRate)
	fmt.Println("Spreading Factor:", sf, "Bandwidth:", bandwidth, "Code Rate:", cr, "devEUI:", d.devEUI)
	t_sym := math.Pow(2, sf) / bandwidth /* (2^(d.uplinkTXInfo.Modulation.GetLora().SpreadingFactor))/d.uplinkTXInfo.Modulation.GetLora().Bandwidth */
	t_preamble := (8 + 4.25) * t_sym     // 8 symbols preamble, as stated in LoRaWAN 1.0.3 spec, plus 4.25 symbols for the header
	fmt.Println("t_sym:", t_sym, "t_preamble:", t_preamble, "devEUI:", d.devEUI)
	payload_symbols_number := 8 + math.Max(math.Ceil((8*14-4*sf+28+16-20*0)/(4*(sf-2*0)))*(cr+4), 0)
	fmt.Println("payload_symbols_number:", payload_symbols_number, "devEUI:", d.devEUI)
	t_payload := payload_symbols_number * t_sym
	fmt.Println("t_payload:", t_payload, "devEUI:", d.devEUI)
	t_packet := t_preamble + t_payload
	fmt.Println("t_packet:", t_packet, "devEUI:", d.devEUI)

	return time.Duration(t_packet * 1000000000)
}
