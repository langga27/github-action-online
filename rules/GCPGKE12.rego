package rules

detect_private_cluster(resource) {
    indexed := resource.private_cluster_config[_]
    not indexed.enable_private_endpoint == true
}
detect_private_cluster(resource) {
    indexed := resource.private_cluster_config[_]
    not indexed.enable_private_nodes == true
}

deny[msg] {
  resource := input.resource.google_container_cluster[name]
  detect_private_cluster(resource)
  

  msg := {
    # Mandatory fields
    "publicId": "GCPGKE12",
    "title": "GCPGKE12: Private Cluster",
    "severity": "high",
    "msg": sprintf("resource.google_container_cluster[%s]", [name]),
    # Optional fields
    "issue": "Public access to GKE cluster control plane and cluster nodes must be restricted. Private clusters must be used to allow to run nodes without external IP addresses and run cluster control plane without publicly reachable endpoint",
    "impact": "GKE cluster that are publically accessible may lead to unauthorized access by malicious user.",
    "remediation": "Please provision the cluster as private. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
    "references": ["https://code.pruconnect.net/projects/RTSRETM/repos/aks"],
  }
}