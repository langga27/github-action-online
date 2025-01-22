# resource_changes[0].change.after.site_config[0].minimum_tls_version
package rules

detect_tls_https_azasv05_windows(resource) {
	not resource.https_only == true
}

detect_tls_https_azasv05_windows(resource) {
	site := resource.site_config[_]
    not site.minimum_tls_version >= "1.2"
}

detect_tls_https_azasv05_windows(resource) {
	site := resource.site_config[_]
    not site.scm_minimum_tls_version >= "1.2"
}

deny[msg] {
    resource := input.resource.azurerm_windows_web_app[name]
    detect_tls_https_azasv05_windows(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZASV05-WINDOWSWEBAPP",
        "title": "AZASV05: TLS version 1.2 is not enabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_windows_web_app[%s]", [name]),
        # Optional fields
        "issue": "App Service must only be accessible over HTTPS. Function App must use approved version of TLS",
        "impact": "Versions lower then TLS 1.2 is susceptible to attack by malicious user.",
        "remediation": "Please enable HTTPS only and use TLS 1.2 when provisioning the resource. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
        "references": ""
    }
}