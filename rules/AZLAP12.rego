package rules

deny[msg] {
    resource := input.resource.azurerm_logic_app_workflow[name]
    not input.resource.azurerm_logic_app_workflow.access_control.content

    msg := {
        # Mandatory Fields
        "publicId": "AZLAP12",
        "title": "AZLAP12: Inbound Ip Addresses that can access run history data must be restricted",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_logic_app_workflow[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Logic App that are provisioned must restrict Inbound IP address that can access run history data.",
        "impact": "Without Ip restriction, malicious and unauthorize user may potentially access run history data, causing data loss.",
        "remediation": "Please restrict the inbound IP addresses that can access run history data when provisioning Azure Logic App. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
