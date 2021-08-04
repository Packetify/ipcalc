package ipv4calc

import (
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

func TestIsPtpLink(t *testing.T) {
	for i := 0; i < 100; i++ {
		_, randIPNet, _ := net.ParseCIDR(getRandomIpNet())
		if subnet, _ := randIPNet.Mask.Size(); subnet == 31 {
			if IsPtpLink(*randIPNet) != true {
				t.Errorf("IsPtpLink(%s) = %v\n", randIPNet.String(), IsPtpLink(*randIPNet))
			}
		} else {
			if IsPtpLink(*randIPNet) != false {
				t.Errorf("IsPtpLink(%s) = %v\n", randIPNet.String(), IsPtpLink(*randIPNet))
			}
		}
	}
}
func TestNew(t *testing.T) {
	count := 0
	go func(){
		for{
			t.Log(count)
			time.Sleep(time.Second*10)
		}
	}()
	for i := 0; i < 10000; i++ {
		count++
		randIP := getRandomIpNet()
		myip := New(randIP)
		ipcalcRes := getIPCalcResult(randIP)
		if ipcalcRes["Address"] != myip.IP.String() {
			t.Errorf("Address: %s", myip.String())
			t.Error("\n" + myip.ToString())

		}
		if ipcalcRes["Netmask"] != net.IP(myip.Mask).To4().String() {
			t.Errorf("Netmask: %s", myip.String())
			t.Error("\n" + myip.ToString())
		}

		if ipcalcRes["Wildcard"] != myip.GetWildcard().String() {
			t.Errorf("wildcard: %s", myip.String())
			t.Error("\n" + myip.ToString())

		}
		if cidr,_:=myip.Mask.Size();cidr==32{
			if ipcalcRes["Hostroute"] != myip.GetNetworkAddr().String() {
				t.Errorf("Hostroute: %s", myip.String())
				t.Error("\n" + myip.ToString())

			}
		}else{
			if cidr <31{
				if ipcalcRes["Broadcast"] != myip.GetBroadCastIP().String() {
					t.Errorf("Broadcast: %s", myip.String())
					t.Error("\n" + myip.ToString())
				}
			}

			if ipcalcRes["Network"] != myip.GetNetworkAddr().String() {
				t.Errorf("Network: %s", myip.String())
				t.Error("\n" + myip.ToString())

			}

			if ipcalcRes["HostMin"] != myip.GetMinHost().String() {
				t.Errorf("HostMin: %s", myip.String())
				t.Error("\n" + myip.ToString())
			}
			if ipcalcRes["HostMax"] != myip.GetMaxHost().String() {
				t.Errorf("HostMax: %s", myip.String())
				t.Error("\n" + myip.ToString())
			}
		}

	}

}

func getIPCalcResult(ipnet string) map[string]string {
	keys := []string{"Address", "Netmask", "Wildcard", "Network", "HostMin", "HostMax", "Broadcast","Hostroute"}
	resMap := make(map[string]string)
	IPRegex, _ := regexp.Compile("([0-9]{1,3}\\.){3}[0-9]{1,3}")
	for _, k := range keys {
		ipcalcOut, err := exec.Command("ipcalc", ipnet).Output()
		if err != nil {
			panic("ipcalc error")
		}
		IPCalcRegex, _ := regexp.Compile(fmt.Sprintf("%s:\\s+([0-9]{1,3}\\.){3}[0-9]{1,3}", k))
		tmpstr := IPCalcRegex.FindString(string(ipcalcOut))
		resMap[k] = IPRegex.FindString(tmpstr)
	}
	return resMap
}

func getRandomIpNet() string {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	return fmt.Sprintf("%d.%d.%d.%d/%d", r1.Intn(256), r1.Intn(256), r1.Intn(256), r1.Intn(256), r1.Intn(32)+1)
}
