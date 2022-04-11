package config

import (
	"time"

	"github.com/google/gopacket/pcap"
)

type LiveConfig struct {
	Device       string //= "eth0"
	Snapshot_len int32  //= 1024
	Promiscuous  bool   //= false
	Err          error
	Timeout      time.Duration //= 30 * time.Second
	Handle       *pcap.Handle
}

type PcapConfig struct {
	PcapFile string
	Handle   *pcap.Handle
	Err      error
}
