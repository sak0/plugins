package client

import (
	"context"
	"strconv"
	//"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/client"
)

const (
	LABLE_VLANID = "cloud.yonghui.cn/vlanid"
	LABLE_SUBNET = "cloud.yonghui.cn/subnet"
	LABLE_NETWORK = "cloud.yonghui.cn/network"
)

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