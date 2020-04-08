package docker

import (
	"context"
	"strconv"

	"github.com/docker/engine-api/client"
)

const (
	LABLEPODIP = "infra.tce.io/pod-ip"
)

type DockerClient struct {
	cl	*client.Client
}

func (dc *DockerClient)GetPodIP(containerId string)(string, error){
	container, err := dc.cl.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return "", err
	}
	podIP, ok := container.Config.Labels[LABLEPODIP]
	if !ok {
		return "", err
	}

	return podIP, nil
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