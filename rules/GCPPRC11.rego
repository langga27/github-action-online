package rules

detect_kms_gcpprc11(resource) {
    clusterConfig := resource.cluster_config[_]
    encryptionConfig := clusterConfig.encryption_config[_]
    not encryptionConfig.kms_key_name
}

detect_kms_gcpprc11(resource) {
    clusterConfig := resource.cluster_config[_]
    clusterConfig.encryption_config == []
}

detect_kms_gcpprc11(resource) {
    not resource.cluster_config[0]
}

deny[msg] {
    resource := input.resource.google_dataproc_cluster[name]
    detect_kms_gcpprc11(resource)

    msg := {
        # Mandatory Fields
        "publicId": "GCPPRC11",
        "title": "GCPPRC11: Encryption at Rest",
        "severity": "high",
        "msg": sprintf("input.resource.google_dataproc_cluster[%s]", [name]),
        # Optional Fields
        "issue": "Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud Dataproc encryption",
        "impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the Google's encryption key and the encrypted data.",
        "remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": ""        
    }
}