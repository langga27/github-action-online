package rules

# For static scan
google_container_cluster_missing(resource) {
	resource.network_policy.enabled == true
}

# For tfplan
google_container_cluster_missing(resource) {
    network_policy := resource.network_policy[_]
    network_policy.enabled == true
}

deny[msg] {
    resource := input.resource.google_container_cluster[name]
    not google_container_cluster_missing(resource)

    msg := {
        # Mandatory fields
        "publicId": "GCPGKE14",
        "title": "GCPGKE14: Network Policy",
        "severity": "high",
        "msg": sprintf("resource.google_container_cluster[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_container_cluster",
        "issue": "Network policy must be Enabled for Master and Nodes.",
        "impact": "Network Policies are a crucial feature that allows you to control the communication between pods in your Kubernetes cluster.",
        "remediation": "Please enable the kubernetes network policy. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": ""
    }
}