#!/bin/bash

set -x

sudo docker run --name pktgen -td --restart unless-stopped --cpuset-cpus=3,5,7,9 -p 0.0.0.0:8000:8000 \
                --ulimit memlock=-1 --cap-add IPC_LOCK -v /dev/hugepages:/dev/hugepages \
                -v "$PWD/conf":/opt/bess/bessctl/conf --device=/dev/vfio/vfio --device=/dev/vfio/113 \
                --device=/dev/vfio/114 upf-epc-bess:"$(<VERSION)" -grpc-url=0.0.0.0:10514

sleep 20
sudo docker exec -d -it pktgen ./bessctl http 0.0.0.0 8000
sudo docker exec -it -d pktgen ./bessctl run pktgen
