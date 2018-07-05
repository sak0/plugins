package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	
	"github.com/containernetworking/plugins/plugins/ipam/yhipam/client"	
)

const (
	OpenStackEndpoint = "http://10.0.91.153:35357/v3"
	OpenStackUser     = "admin"
	OpenStackPass     = "e6c5f31b94bb4c4b"
	OpenStackTenant   = "26b33cbba52f41d59d69a6c7e736473b"
)

var (
	Info *log.Logger
	Warning *log.Logger
	Error * log.Logger
)

type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	IPAM       *IPAMConfig `json:"ipam"`
}

type IPAMConfig struct {
	Name      string
	Type      string         `json:"type"`
	Routes    []*types.Route `json:"routes"`
	Addresses []Address      `json:"addresses"`
	DNS       types.DNS      `json:"dns"`
	SubnetID  string         `json:"subnet"`
	NetworkID string         `json:"network"`	
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

func init(){
	errFile, err:=os.OpenFile("/var/log/cnierrors.log",os.O_CREATE|os.O_WRONLY|os.O_APPEND,0666)
	if err!=nil{
		panic(err)
	}
	Info = log.New(os.Stdout,"Info:",log.Ldate | log.Ltime | log.Lshortfile)
	Warning = log.New(os.Stdout,"Warning:",log.Ldate | log.Ltime | log.Lshortfile)
	//Error = log.New(io.MultiWriter(os.Stderr,errFile),"Error:",log.Ldate | log.Ltime | log.Lshortfile)
	Error = log.New(errFile ,"Error:",log.Ldate | log.Ltime | log.Lshortfile)
}

func main() {
	// TODO: implement plugin version
	skel.PluginMain(cmdAdd, cmdGet, cmdDel, version.All, "TODO")
}

func cmdGet(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}

func cmdAdd(args *skel.CmdArgs) error {
	//Error.Printf("%+v\n", args)
	n := Net{}
	if err := json.Unmarshal(args.StdinData, &n); err != nil {
		return err
	}
	
	dc, err := client.NewDockerClient()
	if err != nil {
		return err
	}
	subnetID, err := dc.GetSubnet(args.ContainerID)
	if err != nil || subnetID == "" {
		subnetID = n.IPAM.SubnetID
	}
	netID, err := dc.GetNetwork(args.ContainerID)
	if err != nil || netID == "" {
		netID = n.IPAM.NetworkID
	}
	
	client, err := client.NewOpsClient(OpenStackEndpoint, OpenStackUser, OpenStackPass, OpenStackTenant)
	if err != nil {
		return err
	}
	gw, subnet, err := client.GetSubNetInfo(subnetID)
	if err != nil{
		return err
	}
	ip, _, err := client.GetIpAddr(netID, args.ContainerID)
	if err != nil{
		return err
	}
	
	ipconf := &current.IPConfig{
		Version : "4",
		Gateway : net.ParseIP(gw),
	}
	
	ips, _ := net.LookupIP(ip)
	_, addr, _ := net.ParseCIDR(subnet)
	ipconf.Address = *addr
	ipconf.Address.IP = ips[0]
	
	result := &current.Result{}
	result.DNS = n.IPAM.DNS
	result.Routes = n.IPAM.Routes
	result.IPs = append(result.IPs, ipconf)

	return types.PrintResult(result, "0.2.0")
}

func cmdDel(args *skel.CmdArgs) error {
	//Error.Printf("%+v\n", args)
	client, err := client.NewOpsClient(OpenStackEndpoint, OpenStackUser, OpenStackPass, OpenStackTenant)
	if err != nil {
		return err
	}
	err = client.ReleaseIp(args.ContainerID)
	if err != nil {
		return err
	}
	
	return nil
}