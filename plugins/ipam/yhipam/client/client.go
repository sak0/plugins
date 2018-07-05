package client

import (
	"fmt"
	"context"
    "strconv"
	
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	//"github.com/gophercloud/gophercloud/openstack/utils"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	
	"github.com/docker/engine-api/client"
)

const (
	DEFAULTDOMAIN = "Default"
	DEFAULTREGION = "RegionOne"
	
	LABLE_VLANID = "cloud.yonghui.cn/vlanid"
	LABLE_SUBNET = "cloud.yonghui.cn/subnet"
	LABLE_NETWORK = "cloud.yonghui.cn/network"
)

type OpsClient struct{
	Endpoint		string
	Username		string
	Password		string
	Domain			string
	TenantID		string
	
	Client			*gophercloud.ServiceClient
}

func (oc *OpsClient)GetSubNetInfo(subnetid string)(gw string, subnet string, err error){
	rs := subnets.Get(oc.Client, subnetid)
	sub, err := rs.Extract()
	if err != nil {
		return "", "", err
	}
	//TODO reslove HostRoutes
	return sub.GatewayIP, sub.CIDR, nil
}

func (oc *OpsClient)GetNetInfo(netid string, subnetid string)(vid int, gw string, subnet string, err error){
	rs := subnets.Get(oc.Client, subnetid)
	sub, err := rs.Extract()
	if err != nil {
		return 0, "", "", err
	}
	re := networks.Get(oc.Client, netid)
	net, err := re.Extract()
	if err != nil {
		return 0, "", "", err
	}
	//TODO reslove HostRoutes&vlan
	return net.ProviderVlan, sub.GatewayIP, sub.CIDR, nil
}

func (oc *OpsClient)ReleaseIp(cid string)error{
	lsOpts := ports.ListOpts{
		Name : cid,
	}
	allPages, err := ports.List(oc.Client, lsOpts).AllPages()
	if err != nil {
		return err
	}
	allPorts, err := ports.ExtractPorts(allPages)
	if err != nil {
		return err
	}
	if len(allPorts) > 1 {
		return fmt.Errorf("Port named %s > 1.", cid)
	} else if len(allPorts) < 1{
		return nil
	}
	pid := allPorts[0].ID
	dres := ports.Delete(oc.Client, pid)
	return dres.Err
}

func (oc *OpsClient)GetIpAddr(netid string, cid string)(ipaddr string, mac string, err error){
	pcOpts := ports.CreateOpts{
		Name	  : cid,
		NetworkID : netid,
	}
	res := ports.Create(oc.Client, pcOpts)
	port, err := res.Extract()
	if err != nil{
		return "", "", nil
	}
	return port.FixedIPs[0].IPAddress, port.MACAddress, nil
}

func NewOpsClient(ep string, user string, pass string, tenant string)(*OpsClient, error){
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: ep,
		Username: user,
		Password: pass,
		DomainName: DEFAULTDOMAIN,
		TenantID: tenant,
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, err
	}
	client, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Region: DEFAULTREGION,
	})
	if err != nil {
		return nil, err
	}
	oc := &OpsClient{
		Endpoint : ep,
		Username : user,
		Password : pass,
		Domain: DEFAULTDOMAIN,
		TenantID: tenant,
		Client	: client,
	}
	return oc, nil
}

type DockerClient struct {
	cl	*client.Client
}

func (dc *DockerClient)GetVlanID(containerId string)(int, error){
	container, err := dc.cl.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return 0, err
	}
	vlanid, ok := container.Config.Labels[LABLE_VLANID]
	if !ok {
		return 0, err
	}
	vid, err := strconv.Atoi(vlanid)
	if err != nil || vid <= 0 {
		return 0, err
	}
	return vid, nil
}

func (dc *DockerClient)GetSubnet(containerId string)(string, error){
	container, err := dc.cl.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return "", err
	}
	subnet, ok := container.Config.Labels[LABLE_SUBNET]
	if !ok {
		return "", err
	}
	return subnet, nil
}

func (dc *DockerClient)GetNetwork(containerId string)(string, error){
	container, err := dc.cl.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return "", err
	}
	net, ok := container.Config.Labels[LABLE_NETWORK]
	if !ok {
		return "", err
	}
	return net, nil
}

func NewDockerClient()(*DockerClient ,error){
	c, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	cli := &DockerClient{
		cl : c,
	}
	return cli, nil
}