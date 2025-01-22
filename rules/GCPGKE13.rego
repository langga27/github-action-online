package rules

# need to align with CARA

detect_cidr_for_access_via_https(resource) {
    indexed := resource.master_authorized_networks_config[_]
    indexed.cidr_blocks
}

deny[msg] {
  resource := input.resource.google_container_cluster[name]
  not detect_cidr_for_access_via_https(resource)
  

  msg := {
    # Mandatory fields
    "publicId": "GCPGKE13",
    "title": "GCPGKE13: Master Authorized Networks",
    "severity": "high",
    "msg": sprintf("resource.google_container_cluster[%s]", [name]),
    # Optional fields
    "issue": "Master authorized Networks must be set to Enable to allow specific CIDR ranges and IP addresses in those ranges to access cluster control plane endpoint using HTTPS",
    "impact": "Without specifying CIDR ranges and IP addresses to the master authorized networks, there is a risk where malicious user can compromise the cluster.",
    "remediation": "Please set the CIDR ranges or IP Addresses to the master authorized network. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
    "references": [""],
  }
}