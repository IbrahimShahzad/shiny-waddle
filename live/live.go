package live

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func FindnPrintAllDevices() error {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
	return nil
}
