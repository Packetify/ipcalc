# ipcalc
IP Calculator Package Written in Go

## Install

```bash
go get -u github.com/Packetify/ipcalc/ipv4calc
```

## Example

```go
package main

import (
	"fmt"
	"github.com/Packetify/ipcalc/ipv4calc"
)

func main() {

	myip := ipv4calc.New("192.168.1.102/24")

	brdIP := myip.GetBroadCastIP()
	netIP := myip.GetNetworkAddr()
	
	fmt.Println(myip,brdIP,netIP)
}

```

```go
package main

import (
	"fmt"
	"net"
	"github.com/Packetify/ipcalc/ipv4calc"
)

func main() {

	ipInfo := net.IPNet{
		IP:   net.IP{192, 168, 1, 1},
		Mask: net.IPMask{255, 255, 255, 0},
	}
	
	myip := ipv4calc.New(ipInfo)

	brdIP := myip.GetBroadCastIP()
	netIP := myip.GetNetworkAddr()
	fmt.Println(myip,brdIP,netIP)
}

```
