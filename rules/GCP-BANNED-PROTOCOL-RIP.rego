package rules
import future.keywords.in

check_gcp_banned_protocol_rip(resource) {
    # Expand the range of ports and compare with banPorts
    banPorts := [520]
    port_range := resource.allow[_].ports[_]
    ports := split(port_range,"-")
    listOfNumbers := numbers.range(to_number(ports[0]),to_number(ports[1]))
    protocol := resource.allow[_].protocol
    protocol == "udp"
    some listOfNumbers[_] in banPorts
}

check_gcp_banned_protocol_rip(resource) {
    # Check specifically defined port
    banPorts := [520]
    port_range := resource.allow[_].ports[_]
    protocol := resource.allow[_].protocol
    protocol == "udp"
    to_number(port_range) == banPorts[_]
}

deny[msg] {
    resource := input.resource.google_compute_firewall[name]
    check_gcp_banned_protocol_rip(resource)
    exception(name)
    exception_cidr(resource)
    
    msg := {
        # Mandatory fields
        "name": [name],
        "publicId": "GCP-BANNED-PROTOCOL-RIP",
        "title": "Banned Protocols RIP (udp 520)",
        "severity": "high",
        "msg": sprintf("resource.google_compute_firewall[%s]", [name]),
        "issue": "RIP port port 520 via UDP shall not be used.",
        "impact": "Insecure routing protocol used for static route creation which is vulnerable to route injection attack by threat actor.",
        "remediation": "Please remove the use of rip port 520 via UDP. You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
        "references": [""],
    }
}