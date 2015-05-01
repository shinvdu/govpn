package govpn

import (
	"net"
	"time"
)

type UDPCPR net.UDPConn

var (
	cprCycle  time.Duration
	cprEnable bool = false
)

// Initialize Constant Packet Rate. rate is KiB/s.
func CPRInit(rate int) {
	if rate <= 0 {
		return
	}
	NoiseEnable = true
	cprEnable = true
	cprCycle = time.Second / time.Duration(rate*(1<<10)/MTU)
	heartbeatPeriod = cprCycle
}
