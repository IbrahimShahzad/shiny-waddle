package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/IbrahimShahzad/shiny-waddle/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func openFile(pathToFile string) (*pcap.Handle, error) {
	handle, err := pcap.OpenOffline(pathToFile)
	if err != nil {
		return nil, fmt.Errorf("error returned for nonexistent file: %v", err)
	}
	return handle, nil
}

func printPacket(packet gopacket.Packet) {
	printApplicationLayer := false
	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeSIP {
			printApplicationLayer = true
		}
	}
	sipLayer := packet.ApplicationLayer()
	if sipLayer != nil && printApplicationLayer {
		fmt.Println("Application layer/Payload found.")
		sipContents := sipLayer.LayerContents()
		if string(sipContents) != "" {

			fmt.Printf("\n%s\n\n", sipContents)
		}
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

// Use go command line subcommand for either live or offline cases
func parseArgs() (string, error) {
	var filePath string
	flag.StringVar(&filePath, "f", "", "-f /home/pcap/sample.pcap")
	flag.Parse()
	if filePath == "" {
		return filePath, fmt.Errorf("file not specified")
	}
	return filePath, nil
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func LogFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var pcapConfig config.PcapConfig

func main() {

	mode := "offline"

	path, err := parseArgs()
	checkError(err)

	var packetSource *gopacket.PacketSource
	switch mode {
	case "offline":
		pcapConfig.PcapFile = path // should be dont in parseArgs
		pcapConfig.Handle, pcapConfig.Err = openFile(path)
		checkError(pcapConfig.Err)
		packetSource = gopacket.NewPacketSource(pcapConfig.Handle, pcapConfig.Handle.LinkType())

	default:
		fmt.Println("Empty Case")
		os.Exit(1)

	}

	for packet := range packetSource.Packets() {
		// Process packet here
		printPacket(packet)
	}
}
