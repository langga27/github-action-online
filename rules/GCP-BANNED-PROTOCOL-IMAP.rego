package rules
import future.keywords.in

check_gcp_banned_protocol_imap(resource) {
    # Expand the range of ports and compare with banPorts
    banPorts := [143]
    port_range := resource.allow[_].ports[_]
    ports := split(port_range,"-")
    listOfNumbers := numbers.range(to_number(ports[0]),to_number(ports[1]))
    protocol := resource.allow[_].protocol
    targetCidrs := resource.destination_ranges
    checkCidr := net.cidr_contains("10.0.0.0/8", targetCidrs[_])
    not checkCidr
    protocol == "tcp"
    some listOfNumbers[_] in banPorts
}

check_gcp_banned_protocol_imap(resource) {
    # Expand the range of ports and compare with banPorts
    banPorts := [143]
    port_range := resource.allow[_].ports[_]
    ports := split(port_range,"-")
    listOfNumbers := numbers.range(to_number(ports[0]),to_number(ports[1]))
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    some listOfNumbers[_] in banPorts
}

check_gcp_banned_protocol_imap(resource) {
    # Check specifically defined port
    banPorts := [143]
    port_range := resource.allow[_].ports[_]
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    to_number(port_range) == banPorts[_]
}

deny[msg] {
    resource := input.resource.google_compute_firewall[name]
    check_gcp_banned_protocol_imap(resource)
    exception(name)
    exception_cidr(resource)
    
    msg := {
        # Mandatory fields
        "name": [name],
        "publicId": "GCP-BANNED-PROTOCOL-IMAP",
        "title": "Banned Protocols IMAP (tcp 143)",
        "severity": "high",
        "msg": sprintf("resource.google_compute_firewall[%s]", [name]),
        "issue": "IMAP ports (143) via TCP shall not be used as these are insecure ports.",
        "impact": "Internet Message Access Protocol which is not an authorised email protocol to be used within Prudentials.",
        "remediation": "Please remove the use of IMAP port (143). You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
        "references": [""],
    }
}