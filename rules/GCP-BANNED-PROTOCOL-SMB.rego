package rules
import future.keywords.in

check_gcp_banned_protocol_smb(resource) {
    # Expand the range of ports and compare with banPorts
    banPorts := [445]
    port_range := resource.allow[_].ports[_]
    ports := split(port_range,"-")
    listOfNumbers := numbers.range(to_number(ports[0]),to_number(ports[1]))
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    some listOfNumbers[_] in banPorts
}

check_gcp_banned_protocol_smb(resource) {
    # Check specifically defined port
    banPorts := [445]
    port_range := resource.allow[_].ports[_]
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    to_number(port_range) == banPorts[_]
}

deny[msg] {
    resource := input.resource.google_compute_firewall[name]
    check_gcp_banned_protocol_smb(resource)
    exception(name)
    exception_cidr(resource)
    
    msg := {
        # Mandatory fields
        "name": [name],
        "publicId": "GCP-BANNED-PROTOCOL-SMB",
        "title": "Banned Protocols SMB (tcp 445)",
        "severity": "high",
        "msg": sprintf("resource.google_compute_firewall[%s]", [name]),
        "issue": "SMB ports (445) via TCP shall not be used unless it is within Prudential internal networks (within 10.0.0.0/8).",
        "impact": "File sharing protocol which is often exploited for malware propagation.",
        "remediation": "Please remove the use of SMB ports (445). You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
        "references": [""],
    }
}