package rules
import future.keywords.in

chiper_value = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
]

profile_check(resource) {
    customFeature := resource.custom_features[_]
    customFeature in chiper_value
}

deny[msg] {
    resource := input.resource.google_compute_ssl_policy[name]
    input.resource.google_compute_global_forwarding_rule
    not profile_check(resource)

    msg := {
        # Mandatory fields
        "publicId": "GCPLBL04",
        "title": "GCPLBL04: SSL Profile Policy",
        "severity": "high",
        "msg": sprintf("resource.google_compute_ssl_policy[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_compute_ssl_policy",
        "issue": "A profile must be pre-configured in SSL policy to allow SSL cipher in accordance to GISP Encryption Standard. The SSL policy will affect the connections between clients and the Load balancer, it does not affect the connections between the load balancer and the backends.",
        "impact": "Using non GISP endorsed SSL Cipher is susceptible to attack by malicious user.",
        "remediation": "Please configure to only use GISP endorsed SSL Cipher. ou may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETB/repos/gcp-foundation"        
    }
}