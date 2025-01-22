package rules

deny[msg] {
    resource := input.resource.azurerm_kubernetes_cluster[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory Fields
        "publicId": "AZAKS02",
        "title": "AZAKS02: Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_kubernetes_cluster[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Kubernetes Service instances that are provisioned must have logging of Kubernetes Service Security log enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning AKS cluster. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/aks"        
    }
}
