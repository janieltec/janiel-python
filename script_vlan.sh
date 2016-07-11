#!/bin/bash

ip addr del 10.0.0.4/8 dev h4-eth0
ip link add link h4-eth0 name h4-eth0.2 type vlan id 110
ip addr add 10.0.0.4/8 dev h4-eth0.2
ip link set dev h4-eth0.2 up