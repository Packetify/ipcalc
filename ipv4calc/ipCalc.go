package ipv4calc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
)

type IPCalc struct {
	*net.IPNet
}

func New(IPNet interface{}) IPCalc {

	if ipInfo, ok := IPNet.(net.IPNet); ok == true {
		return IPCalc{&ipInfo}
	}

	if ipInfo, ok := IPNet.(*net.IPNet); ok == true {
		return IPCalc{ipInfo}
	}

	if ipInfo, ok := IPNet.(string); ok == true {
		theIP, IPCIDR, err := net.ParseCIDR(ipInfo)

		if err != nil {
			panic(err)
		}
		return IPCalc{&net.IPNet{IP: theIP, Mask: IPCIDR.Mask}}
	}

	if ipInfo, ok := IPNet.(net.IP); ok == true {
		newIPNet := net.IPNet{
			IP:   ipInfo,
			Mask: ipInfo.DefaultMask(),
		}
		return IPCalc{&newIPNet}
	}
	panic(errors.New("error while create New ipcalc instance"))
}

func (ipcalc *IPCalc) GetBroadCastIP() net.IP {
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	wildcard := ^IPToBinary(net.IP(ipcalc.Mask))
	binIP := IPToBinary(ipcalc.IP)

	binary.BigEndian.PutUint32(resIP, binIP|wildcard)
	return resIP
}

func (ipcalc *IPCalc) GetNetworkAddr() net.IP {
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	subnetIP := IPToBinary(net.IP(ipcalc.Mask))
	binIP := IPToBinary(ipcalc.IP)

	binary.BigEndian.PutUint32(resIP, binIP&subnetIP)
	return resIP
}

func (ipcalc *IPCalc) GetValidHosts() int {
	netMaskLen, _ := ipcalc.Mask.Size()
	validHosts := int(math.Pow(2, float64(32-netMaskLen))) - 2
	if validHosts < 1 || netMaskLen == 32 {
		validHosts = 1
	}
	if netMaskLen == 31{
		validHosts = 2
	}
	return validHosts
}

func (ipcalc *IPCalc) GetClass() byte {
	octet1 := ipcalc.IP.To4()[0]

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
	if cidr,_:=ipcalc.Mask.Size();cidr ==31{
		return ipcalc.GetNetworkAddr()
	}
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	ipbin := IPToBinary(ipcalc.GetNetworkAddr()) + 1
	binary.BigEndian.PutUint32(resIP, ipbin)
	return resIP
}

func (ipcalc *IPCalc)GetMaxHost()net.IP{
	if cidr,_:=ipcalc.Mask.Size();cidr ==31{
		return ipcalc.GetBroadCastIP()
	}
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	ipbin := IPToBinary(ipcalc.GetBroadCastIP()) - 1
	binary.BigEndian.PutUint32(resIP, ipbin)
	return resIP
}

func (ipcalc *IPCalc) ToString() string {
	outSTR := fmt.Sprintf("Address:\t%-15s\t%-37s\n", ipcalc.IP.String(), IPToBinarySTR(ipcalc.IP))
	outSTR += fmt.Sprintf("Netmask:\t%-15s\t%-37s\n", net.IP(ipcalc.Mask).To4(), IPToBinarySTR(net.IP(ipcalc.Mask)))
	outSTR += fmt.Sprintf("Wildcard:\t%-15s\t%-37s\n", ipcalc.GetWildcard(), IPToBinarySTR(ipcalc.GetWildcard().To4()))
	outSTR += fmt.Sprint("=>\n")
	if cidr,_ := ipcalc.Mask.Size();cidr == 32{
		outSTR += fmt.Sprintf("Hostroute:\t%-15s\t%-37s\n", ipcalc.GetNetworkAddr().String(), IPToBinarySTR(ipcalc.GetNetworkAddr()))
	}else{
		outSTR += fmt.Sprintf("Network:\t%-15s\t%-37s\n", ipcalc.GetNetworkAddr().String(), IPToBinarySTR(ipcalc.GetNetworkAddr()))
		outSTR += fmt.Sprintf("HostMin:\t%-15s\t%-37s\n", ipcalc.GetMinHost(), IPToBinarySTR(ipcalc.GetMinHost()))
		outSTR += fmt.Sprintf("HostMax:\t%-15s\t%-37s\n", ipcalc.GetMaxHost(), IPToBinarySTR(ipcalc.GetMaxHost()))
		if cidr <31{
			outSTR += fmt.Sprintf("Brodcast:\t%-15s\t%-37s\n", ipcalc.GetBroadCastIP().String(), IPToBinarySTR(ipcalc.GetBroadCastIP()))
		}
	}
	outSTR += fmt.Sprintf("Hosts:\t\t%d \t\tclass %c ,%s\n", ipcalc.GetValidHosts(), ipcalc.GetClass(), strings.Join(ipcalc.LookUp(),", "))
	return outSTR
}

//http://www.ietf.org/rfc/rfc1918.txt
func IsPrivate(ip net.IP) bool {
	_, rng1, _ := net.ParseCIDR("10.0.0.0/8")
	_, rng2, _ := net.ParseCIDR("172.16.0.0/12")
	_, rng3, _ := net.ParseCIDR("192.168.0.0/16")
	if rng1.Contains(ip) || rng2.Contains(ip) || rng3.Contains(ip) {
		return true
	}
	return false
}

//http://www.ietf.org/rfc/rfc3330.txt
func IsAPIPA(ip net.IP) bool {
	if _, rng1, _ := net.ParseCIDR("169.254.0.0/16"); rng1.Contains(ip) {
		return true
	}
	return false
}

//http://www.ietf.org/rfc/rfc1700.txt
func IsLoopback(ip net.IP) bool {
	if _, rng1, _ := net.ParseCIDR("127.0.0.0/8"); rng1.Contains(ip) {
		return true
	}
	return false
}

//http://www.ietf.org/rfc/rfc3171.txt
func IsMulticast(ip net.IP) bool {
	if _, rng1, _ := net.ParseCIDR("224.0.0.0/4"); rng1.Contains(ip) {
		return true
	}
	return false
}

//http://www.ietf.org/rfc/rfc3021.txt point to point
func IsPtpLink(ip net.IPNet) bool {
	one, _ := ip.Mask.Size()
	if one == 31 {
		return true
	}
	return false
}

func (ipcalc IPCalc) LookUp() []string {
	lookupList := make([]string,0)

	if IsPrivate(ipcalc.IP) {
		lookupList = append(lookupList,"Private Internet")
	}
	if IsMulticast(ipcalc.IP) {
		lookupList = append(lookupList,"Multicast")
	}
	if IsAPIPA(ipcalc.IP) {
		lookupList = append(lookupList,"APIPA")
	}
	if IsLoopback(ipcalc.IP) {
		lookupList = append(lookupList,"Loopback")
	}
	if IsPtpLink(*ipcalc.IPNet) {
		lookupList = append(lookupList,"PtP Link")
	}
	return lookupList
}

func IPToBinary(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func IPToBinarySTR(ip net.IP) string {
	IPBinSTR := fmt.Sprintf("%032b", IPToBinary(ip))
	octetCount := 0
	var resSTR string
	for bit := 0; bit < len(IPBinSTR); bit++ {
		octetCount++
		resSTR = resSTR + string(IPBinSTR[bit])
		if octetCount == 8 && bit != len(IPBinSTR)-1 {
			octetCount = 0
			resSTR += "."
		}

	}
	return resSTR
}

func (ipcalc IPCalc) GetWildcard() net.IP {
	wildcard := ^IPToBinary(net.IP(ipcalc.Mask))
	resIP := make(net.IP, len(ipcalc.IP.To4()))
	binary.BigEndian.PutUint32(resIP, wildcard)
	return resIP
}
