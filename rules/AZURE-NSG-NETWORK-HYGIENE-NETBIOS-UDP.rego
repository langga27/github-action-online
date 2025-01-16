package rules
import future.keywords.in

##### SOUR
## Testing Only
#This one for range
check_port_netbios_udp(resource) { 
	banPorts := [137]
	portRange := resource.source_port_ranges[_]
	splitedPorts := split(portRange,"-")
    portRangeList := numbers.range(to_number(splitedPorts[0]),to_number(splitedPorts[1]))
	some portRangeList[_] in banPorts
}

check_port_netbios_udp(resource) { 
	banPorts := [138]
	portRange := resource.source_port_ranges[_]
	splitedPorts := split(portRange,"-")
    portRangeList := numbers.range(to_number(splitedPorts[0]),to_number(splitedPorts[1]))
	some portRangeList[_] in banPorts
}

check_port_netbios_udp(resource) { 
	banPorts := [137]
	portRange := resource.source_port_ranges[_]
	to_number(portRange) in banPorts
}

check_port_netbios_udp(resource) { 
	banPorts := [138]
	portRange := resource.source_port_ranges[_]
	to_number(portRange) in banPorts
}

#This one for individual string type
check_port_netbios_udp(resource) { 
	resource.source_port_range == "137"
}

check_port_netbios_udp(resource) { 
	resource.source_port_range == "138"
}
#this one for individual num type
check_port_netbios_udp(resource) { 
	resource.source_port_range == 137
}

check_port_netbios_udp(resource) { 
	resource.source_port_range == 138
}

##### DEST
#This one for range
check_port_netbios_udp(resource) { 
	banPorts := [137]
	portRange := resource.destination_port_ranges[_]
	splitedPorts := split(portRange,"-")
    portRangeList := numbers.range(to_number(splitedPorts[0]),to_number(splitedPorts[1]))
	some portRangeList[_] in banPorts
}

check_port_netbios_udp(resource) { 
	banPorts := [138]
	portRange := resource.destination_port_ranges[_]
	splitedPorts := split(portRange,"-")
    portRangeList := numbers.range(to_number(splitedPorts[0]),to_number(splitedPorts[1]))
	some portRangeList[_] in banPorts
}

check_port_netbios_udp(resource) { 
	banPorts := [137]
	portRange := resource.destination_port_ranges[_]
	to_number(portRange) in banPorts
}

check_port_netbios_udp(resource) { 
	banPorts := [138]
	portRange := resource.destination_port_ranges[_]
	to_number(portRange) in banPorts
}


#This one for individual string type
check_port_netbios_udp(resource) { 
	resource.destination_port_range == "137"
}

check_port_netbios_udp(resource) { 
	resource.destination_port_range == "138"
}
#this one for individual num type
check_port_netbios_udp(resource) { 
	resource.destination_port_range == 137
}

check_port_netbios_udp(resource) { 
	resource.destination_port_range == 138
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
	sour_prefixes := resource.source_address_prefixes[_]
	not net.cidr_contains("10.0.0.0/8", sour_prefixes)
}
check_cidr(resource) {
	dest_prefixes := resource.destination_address_prefixes[_]
	not net.cidr_contains("10.0.0.0/8", dest_prefixes)
}


deny[msg] {
	resource := input.resource.azurerm_network_security_rule[name]
	resource.protocol == "Udp"
	check_port_netbios_udp(resource)
	check_cidr(resource)
	msg := {
		# Mandatory fields
		"publicId": "AZURE-NSG-NETWORK-HYGIENE-NETBIOS-UDP", #please change the public id
		"title": "Network Hygiene Netbios (udp 137/138)",
		"severity": "high",
	    "msg": sprintf("resource.azurerm_network_security_rule[%s]", [name]),
		"issue": "Netbios ports (137/138) via UDP shall not be used, unless it is within Prudential internal network (within 10.0.0.0/8)",
		"impact": "Netbios default port should not be accessible from un-trusted network for administrative purpose.",
		"remediation": "Please remove the use of netbios ports (137/138). You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
		"references": [""],
	}
}
