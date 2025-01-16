package rules
import future.keywords.in

##### SOUR
# This one for range
check_port_vnc(resource) { 
    banPorts := numbers.range(5800, 5900)
    srcRange := resource.source_port_ranges[_]
    splitRange := split(srcRange, "-")
    srcPortRange := numbers.range(to_number(splitRange[0]), to_number(splitRange[1]))
    some srcPortRange[_] in banPorts
}

check_port_vnc(resource) { 
    banPorts := numbers.range(5800, 5900)
    srcRange := resource.source_port_ranges[_]
    to_number(srcRange) in banPorts
}

# This one for individual string type
check_port_vnc(resource) { 
    banPorts := numbers.range(5800, 5900)
    srcRangeStr := resource.source_port_range
    to_number(srcRangeStr) in banPorts
}

##### DEST
# This one for range
check_port_vnc(resource) { 
    banPorts := numbers.range(5800, 5900)
    destRange := resource.destination_port_ranges[_]
    splitRange := split(destRange, "-")
    destPortRange := numbers.range(to_number(splitRange[0]), to_number(splitRange[1]))
    some destPortRange[_] in banPorts
}

check_port_vnc(resource) { 
    banPorts := numbers.range(5800, 5900)
    destRange := resource.destination_port_ranges[_]
    to_number(destRange) in banPorts
}

# This one for individual string type
check_port_vnc(resource) { 
    banPorts := numbers.range(5800, 5900)
    destRangeStr := resource.destination_port_range
    to_number(destRangeStr) in banPorts
}

check_cidr(resource) {
    resource.source_address_prefix != null
    not net.cidr_contains("10.0.0.0/8", resource.source_address_prefix)
}
check_cidr(resource) {
    resource.destination_address_prefix != null
    not net.cidr_contains("10.0.0.0/8", resource.destination_address_prefix)
}
check_cidr(resource) {
    srcPrefixes := resource.source_address_prefixes[_]
    not net.cidr_contains("10.0.0.0/8", srcPrefixes)
}
check_cidr(resource) {
    destPrefixes := resource.destination_address_prefixes[_]
    not net.cidr_contains("10.0.0.0/8", destPrefixes)
}

deny[msg] {
	resource := input.resource.azurerm_network_security_rule[name]
	resource.protocol == "Tcp"
	check_port_vnc(resource)
	check_cidr(resource)
	msg := {
		# Mandatory fields
		"publicId": "AZURE-NSG-NETWORK-HYGIENE-VNC", #please change the public id
		"title": "Network Hygiene VNC (tcp 5800-5900)",
		"severity": "high",
	    "msg": sprintf("resource.azurerm_network_security_rule[%s]", [name]),
		"issue": "VNC ports (5800-5900) via TCP shall not be used, unless it is within Prudential internal network (within 10.0.0.0/8)",
		"impact": "VNC default port should not be accessible from un-trusted network for administrative purpose.",
		"remediation": "Please remove the use of VNC ports (5800-5900). You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
		"references": [""],
	}
}