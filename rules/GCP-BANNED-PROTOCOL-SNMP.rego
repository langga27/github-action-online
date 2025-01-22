package rules
import future.keywords.in

check_gcp_banned_protocol_snmp(resource) {
    # Expand the range of ports and compare with banPorts
    banPorts := [161]
    port_range := resource.allow[_].ports[_]
    ports := split(port_range,"-")
    listOfNumbers := numbers.range(to_number(ports[0]),to_number(ports[1]))
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    some listOfNumbers[_] in banPorts
}

check_gcp_banned_protocol_snmp(resource) {
    # Check specifically defined port
    banPorts := [161]
    port_range := resource.allow[_].ports[_]
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    to_number(port_range) == banPorts[_]
}

check_gcp_banned_protocol_snmp(resource) {
    # Expand the range of ports and compare with banPorts
    banPorts := [162]
    port_range := resource.allow[_].ports[_]
    ports := split(port_range,"-")
    listOfNumbers := numbers.range(to_number(ports[0]),to_number(ports[1]))
    protocol := resource.allow[_].protocol
    protocol == "udp"
    some listOfNumbers[_] in banPorts
}

check_gcp_banned_protocol_snmp(resource) {
    # Check specifically defined port
    banPorts := [162]
    port_range := resource.allow[_].ports[_]
    protocol := resource.allow[_].protocol
    protocol == "udp"
    to_number(port_range) == banPorts[_]
}

deny[msg] {
    resource := input.resource.google_compute_firewall[name]
    check_gcp_banned_protocol_snmp(resource)
    exception(name)
    exception_cidr(resource)
    
    msg := {
        # Mandatory fields
        "name": [name],
        "publicId": "GCP-BANNED-PROTOCOL-SNMP",
        "title": "Banned Protocols SNMP (tcp 161, udp 162)",
        "severity": "high",
        "msg": sprintf("resource.google_compute_firewall[%s]", [name]),
        "issue": "SNMP ports 161 via TCP and SNMP port 162 via UDP shall not be used unless it is within Prudential internal networks (within 10.0.0.0/8).",
        "impact": "Can be exploited to send malformed SNMP trap packets to deceive target system to response with appropriate SNMP data, which can be used for further exploitation.",
        "remediation": "Please remove the use of SNMP port 161 via TCP and 162 via UDP. You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
        "references": [""],
    }
}