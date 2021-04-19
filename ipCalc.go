package ipcalc

import (
	"encoding/binary"
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
		_, IPCIDR, err := net.ParseCIDR(ipInfo)
		if err != nil {
			panic(err)
		}
		res = IPCalc{IPCIDR}
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

func (IPCalc *IPCalc) GetNetworkAddr() net.IP {
	resIP := make(net.IP, len(IPCalc.IP.To4()))
	subnetIP := binary.BigEndian.Uint32(net.IP(IPCalc.Mask).To4())
	binIP := binary.BigEndian.Uint32(IPCalc.IP.To4())

	binary.BigEndian.PutUint32(resIP, binIP&subnetIP)
	return resIP
}
