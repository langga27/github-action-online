package rules

detect_shielded_gcpprc12(resource) {
    clusterConfig := resource.cluster_config[_]
    gkeClusterConfig := clusterConfig.gce_cluster_config[_]
    shieldedInstanceConfig := gkeClusterConfig.shielded_instance_config[_]
    not shieldedInstanceConfig.enable_secure_boot == true
}

detect_shielded_gcpprc12(resource) {
    clusterConfig := resource.cluster_config[_]
    gkeClusterConfig := clusterConfig.gce_cluster_config[_]
    shieldedInstanceConfig := gkeClusterConfig.shielded_instance_config[_]
    not shieldedInstanceConfig.enable_integrity_monitoring == true
}

detect_shielded_gcpprc12(resource) {
    clusterConfig := resource.cluster_config[_]
    gkeClusterConfig := clusterConfig.gce_cluster_config[_]
    shieldedInstanceConfig := gkeClusterConfig.shielded_instance_config[_]
    not shieldedInstanceConfig.enable_vtpm == true
}

detect_shielded_gcpprc12(resource) {
    not resource.cluster_config[0]
}

detect_shielded_gcpprc12(resource) {
    clusterConfig := resource.cluster_config[_]
    not clusterConfig.gce_cluster_config
}

deny[msg] {
    resource := input.resource.google_dataproc_cluster[name]
    detect_shielded_gcpprc12(resource)

    msg := {
        # Mandatory Fields
        "publicId": "GCPPRC12",
        "title": "GCPPRC12: Shielded VM",
        "severity": "high",
        "msg": sprintf("input.resource.google_dataproc_cluster[%s]", [name]),
        # Optional Fields
        "issue": "The settings for Secure Boot, vTPM and Integrity monitoring must be enabled",
        "impact": "Without Shielded VM an attacker can exploit a vulnerability dataproc, giving the attackers access to secrets.",
        "remediation": "Please enable shielded VM. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": ""        
    }
}