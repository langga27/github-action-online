package rules
import future.keywords.in

exception(name) {
    not startswith(name, "shadow_allow_nodes")
}

exception_cidr(resource) {
    not resource.destination_ranges
    targetCidrs := resource.source_ranges
    checkCidr := net.cidr_contains("10.0.0.0/8", targetCidrs[_])
    not checkCidr
}

exception_cidr(resource) {
    not resource.source_ranges
    targetCidrs := resource.destination_ranges
    checkCidr := net.cidr_contains("10.0.0.0/8", targetCidrs[_])
    not checkCidr
}

check_gcp_banned_protocol_all(resource) {
    # Expand the range of ports and compare with banPorts
    resource.allow[_].protocol == "all"
}

deny[msg] {
    resource := input.resource.google_compute_firewall[name]
    check_gcp_banned_protocol_all(resource)
    exception(name)
    
    msg := {
        # Mandatory fields
        "name": [name],
        "publicId": "GCP-BANNED-PROTOCOL-ALL",
        "title": "Banned Protocols ALL (All ports)",
        "severity": "high",
        "msg": sprintf("resource.google_compute_firewall[%s]", [name]),
        "issue": "Firewall should not be allowed to have ALL rules",
        "impact": "Firewall having an ALL rule may expose services to unnecessary risk.",
        "remediation": "Please remove the use of ALL. You may refer to the baseline documents in https://pruo365.sharepoint.com/:b:/r/sites/GROUP-1-HUB/Shared%20Documents/Group%20Governance%20Manual/5.%20GGM%20Policies/Group%20Technology/Group%20Technology/Information%20Security/Group%20Banned%20Protocol%20Standard%20%5B2023%5D.pdf?csf=1&web=1&e=kjAZIK for more details.",
        "references": [""],
    }
}