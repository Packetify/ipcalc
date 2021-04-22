package ipv4calc

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

type IPCalc struct {
	*net.IPNet
}

func New(IPNet interface{}) IPCalc {
	var res IPCalc
	if ipInfo, ok := IPNet.(net.IPNet); ok == true {
		res = IPCalc{&ipInfo}
	}

	if ipInfo, ok := IPNet.(string); ok == true {
		theIP, IPCIDR, err := net.ParseCIDR(ipInfo)

		if err != nil {
			panic(err)
		}
		res = IPCalc{&net.IPNet{IP: theIP, Mask: IPCIDR.Mask}}
	}

	if ipInfo, ok := IPNet.(net.IP); ok == true {
		newIPNet := net.IPNet{
			IP:   ipInfo,
			Mask: ipInfo.DefaultMask(),
		}
		res = IPCalc{&newIPNet}
	}
	return res
}

func (ipcalc *IPCalc) GetBroadCastIP() net.IP {
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	wildcard := ^binary.BigEndian.Uint32(net.IP(ipcalc.Mask).To4())
	binIP := binary.BigEndian.Uint32(ipcalc.IP.To4())

	binary.BigEndian.PutUint32(resIP, binIP|wildcard)
	return resIP
}

func (ipcalc *IPCalc) GetNetworkAddr() net.IP {
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	subnetIP := binary.BigEndian.Uint32(net.IP(ipcalc.Mask).To4())
	binIP := binary.BigEndian.Uint32(ipcalc.IP.To4())

	binary.BigEndian.PutUint32(resIP, binIP&subnetIP)
	return resIP
}

func (ipcalc *IPCalc) GetValidHosts() int {
	netMaskLen, _ := ipcalc.Mask.Size()
	return int(math.Pow(2, float64(32-netMaskLen))) - 2
}

func (ipcalc *IPCalc) GetClass() byte {
	octet1 := ipcalc.IP[0]

	isInRange := func(number, a, b byte) bool {
		if number >= a && number <= b {
			return true
		}
		return false
	}
	switch {
	case isInRange(octet1, 0, 127):
		return 'A'
	case isInRange(octet1, 128, 191):
		return 'B'
	case isInRange(octet1, 192, 223):
		return 'C'
	case isInRange(octet1, 224, 239):
		return 'D'
	case isInRange(octet1, 240, 255):
		return 'E'
	}
	return 1
}

func (ipcalc *IPCalc) GetMinHost() net.IP {
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	ipbin := binary.BigEndian.Uint32(ipcalc.GetNetworkAddr().To4()) + 1
	binary.BigEndian.PutUint32(resIP, ipbin)
	return resIP
}

func (ipcalc *IPCalc) ToString() string {
	outSTR := fmt.Sprintf("Address:\t%s\n", ipcalc.IP.String())
	outSTR += fmt.Sprintf("Netmask:\t%s\n", net.IP(ipcalc.Mask).To4())
	outSTR += fmt.Sprintf("Brodcast:\t%s\n", ipcalc.GetBroadCastIP().String())
	outSTR += fmt.Sprintf("Network:\t%s\n", ipcalc.GetNetworkAddr().String())
	outSTR += fmt.Sprintf("Hosts:\t%d\tclass:%c\n", ipcalc.GetValidHosts(), ipcalc.GetClass())
	return outSTR
}
