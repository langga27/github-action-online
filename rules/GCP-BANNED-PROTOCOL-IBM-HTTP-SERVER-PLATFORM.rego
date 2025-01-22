package rules
import future.keywords.in

check_gcp_banned_protocol_ibm_http_server_platform(resource) {
    # Expand the range of ports and compare with banPorts
    banPorts := [2001]
    port_range := resource.allow[_].ports[_]
    ports := split(port_range,"-")
    listOfNumbers := numbers.range(to_number(ports[0]),to_number(ports[1]))
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    some listOfNumbers[_] in banPorts
}

check_gcp_banned_protocol_ibm_http_server_platform(resource) {
    # Check specifically defined port
    banPorts := [2001]
    port_range := resource.allow[_].ports[_]
    protocol := resource.allow[_].protocol
    protocol == "tcp"
    to_number(port_range) == banPorts[_]
}

deny[msg] {
    resource := input.resource.google_compute_firewall[name]
    check_gcp_banned_protocol_ibm_http_server_platform(resource)
    exception(name)
    exception_cidr(resource)

    msg := {
        # Mandatory fields
        "name": [name],
        "publicId": "GCP-BANNED-PROTOCOL-IBM-HTTP-SERVER-PLATFORM",
        "title": "Banned Protocols IBM-HTTP-SERVER-PLATFORM (tcp 2001)",
        "severity": "high",
        "msg": sprintf("resource.google_compute_firewall[%s]", [name]),
        "issue": "IBM Http Server Platform ports (2001) via TCP shall not be used as these are insecure protocol for common web service admin, unless it is from a trusted network.",
        "impact": "To perform remote administration on a HIS web server, not permitted by policy from external.",
        "remediation": "Please remove the use of IBM Http Server Platform port (2001). You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
        "references": [""],
    }
}