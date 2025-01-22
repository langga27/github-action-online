package rules

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_ecdhe_ecdsa_with_aes128_cbc_sha_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_ecdhe_ecdsa_with_aes256_cbc_sha_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_ecdhe_ecdsa_with_aes256_cbc_sha_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_ecdhe_rsa_with_aes128_cbc_sha_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_ecdhe_rsa_with_aes256_cbc_sha_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_rsa_with_aes128_cbc_sha_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_rsa_with_aes128_gcm_sha256_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_rsa_with_aes256_gcm_sha384_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_rsa_with_aes256_cbc_sha256_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.tls_rsa_with_aes256_cbc_sha_ciphers_enabled == true
}

cipherCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.triple_des_ciphers_enabled == true
}

deny[msg] {
    resource := input.resource.azurerm_api_management[name]
    cipherCheck(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZAPI07",
        "title": "AZAPI07: Weak cipher suite is enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_api_management[%s]", [name]),
        # Optional Fields
        "path": "resource > resource.azurerm_api_management",
        "issue": "Only required cipher suites can be enabled for Azure API Management instance. Any additional weak cipher suite should not be enabled.",
        "impact": "It is required to only enable required cipher suite for API Management instance. Weak cipher suite should not be used as this may lead to brute force attack and potentially data leak.",
        "remediation": "Please only enable required cipher suite for API management. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM"
    }
}