from sigma.backends.logpoint.logpoint import Logpoint
from sigma.pipelines.logpoint.m365 import logpoint_m365_pipeline
from sigma.collection import SigmaCollection


def test_logpoint_o365():
    assert (
        Logpoint(logpoint_m365_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: m365
                        service: threat_management
                    detection:
                        sel:
                            eventName: 'Activity performed by terminated user'
                            eventSource: SecurityComplianceCenter
                            status: success
                        condition: sel
                """
            )
        )
        == [
            'norm_id="Office365" category="ThreatManagement" alert_name="Activity performed by terminated user" event_source="SecurityComplianceCenter" status="success"'
        ]
    )


def test_logpoint_m365_json_structure():
    assert (
        Logpoint(logpoint_m365_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: m365
                        service: threat_management
                    detection:
                        selection:
                            ModifiedProperties.newValue: "test"
                            ModifiedProperties.displayName|startswith: "test2"
                        condition: selection
                """
            )
        )
        == [
            'norm_id="Office365" category="ThreatManagement" modified_property=\'*"newvalue": "test"*\' modified_property=\'*"displayname": "test2*"*\''
        ]
    )


def test_logpoint_m365_nested_json_structure():
    assert (
        Logpoint(logpoint_m365_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: m365
                        service: threat_management
                    detection:
                        selection:
                            ModifiedProperties.object.newValue: "test"
                            ModifiedProperties.object.item.displayName|startswith: "test2"
                        condition: selection
                """
            )
        )
        == [
            'norm_id="Office365" category="ThreatManagement" modified_property=\'*"object"*"newvalue": "test"*\' modified_property=\'*"object"*"item"*"displayname": "test2*"*\''
        ]
    )


def test_logpoint_azure_json_structure_list():
    assert (
        Logpoint(logpoint_m365_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: m365
                    detection:
                        selection:
                            Workload: 'AzureActiveDirectory'
                            ModifiedProperties.NewValue|endswith:
                                - 'Admins'
                                - 'Administrator'
                        condition: selection
                    falsepositives:
                        - PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.
                    level: medium
                """
            )
        )
        == [
            'norm_id="Office365" application="AzureActiveDirectory" modified_property IN [\'*"newvalue": "*Admins"*\', \'*"newvalue": "*Administrator"*\']'
        ]
    )
