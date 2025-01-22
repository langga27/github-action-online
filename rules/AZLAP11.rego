package rules

deny[msg] {
    resource := input.resource.azurerm_logic_app_workflow[name]
    not input.resource.azurerm_logic_app_workflow.access_control.trigger

    msg := {
        # Mandatory Fields
        "publicId": "AZLAP11",
        "title": "AZLAP11: Inbound IP Addresses that trigger Logic App must be restricted",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_logic_app_workflow[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Logic App that are provisioned must restrict Inbound IP address that can trigger the Logic App",
        "impact": "Without Ip restriction, malicious and unauthorize user may potentially trigger the logic app from internet, causing data loss.",
        "remediation": "Please restrict the inbound IP addresses that can trigger the Logic App when provisioning Azure Logic App. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
