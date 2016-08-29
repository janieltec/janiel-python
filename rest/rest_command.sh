#!/bin/bash

#curl -X DELETE -d '{ "rule_id":"7"}' http://localhost:8080/firewall/rules/0000000000000001

#curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001

curl -X POST -d '{"nw_dst": "10.0.0.0/8", "nw_proto": "ICMP"}' http://localhost:8080/firewall/rules/0000000000000001/2
