package rules
import future.keywords.in

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
	resource.protocol == "Icmp"
	resource.access == "Allow"
	check_cidr(resource)
	msg := {
		# Mandatory fields
		"publicId": "AZURE-NSG-NETWORK-HYGIENE-ICMP", #please change the public id
		"title": "Network Hygiene ICMP",
		"severity": "high",
	    "msg": sprintf("resource.azurerm_network_security_rule[%s]", [name]),
		"issue": "ICMP shall not be used, unless it is within Prudential internal network (within 10.0.0.0/8)",
		"impact": "ICMP default port should not be accessible from un-trusted network for administrative purpose.",
		"remediation": "Please remove the use of ICMP. You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
		"references": [""],
	}
}