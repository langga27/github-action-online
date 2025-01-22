package rules

gcp_gke_shielded_nodes_check(resource) {
    not resource.enable_shielded_nodes == true
}

deny[msg] {
	resource := input.resource.google_container_cluster[name]
	gcp_gke_shielded_nodes_check(resource)

	msg := {
		# Mandatory fields
		"publicId": "GCPGKE19",
		"title": "GCPGKE19: Shielded GKE Nodes",
		"severity": "high",
		"msg": sprintf("resource.google_container_cluster[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "Shielded GKE Nodes must be enabled",
		"impact": "Without Shielded GKE Nodes an attacker can exploit a vulnerability in a Pod to exfiltrate bootstrap credentials and impersonate nodes in cluster, giving the attackers access to cluster secrets.",
		"remediation": "Please enable shielded GKE Nodes. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}