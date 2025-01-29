from sigma.backends.logpoint.logpoint import Logpoint
from sigma.pipelines.logpoint.azure import logpoint_azure_pipeline
from sigma.collection import SigmaCollection


def test_logpoint_azure():
    assert (
        Logpoint(logpoint_azure_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: azure
                        service: signinlogs
                    detection:
                        selection:
                            Status: 'Success'
                        selection1:
                            Location|contains: 'Nepal'
                        condition: selection and selection1
                """
            )
        )
        == [
            'norm_id="AzureLogAnalytics" event_type="SigninLogs" status="Success" region="*Nepal*"'
        ]
    )


def test_logpoint_azure_activitylogs():
    assert (
        Logpoint(logpoint_azure_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: azure
                        service: activitylogs
                    detection:
                        selection:
                            CategoryValue: 'Administrative'
                            ResourceProviderValue: 'rtest'
                            ResourceId|contains: 'idtest'
                            OperationNameValue: 'optest'
                        condition: selection
                """
            )
        )
        == [
            'norm_id="MicrosoftAzure" event_category="Administrative" resource="rtest" resource_id="*idtest*" operation="optest"'
        ]
    )


def test_logpoint_azure_json_structure():
    assert (
        Logpoint(logpoint_azure_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: azure
                        service: signinlogs
                    detection:
                        selection:
                            TargetResources.ModifiedProperties.DisplayName: 'StrongAuthenticationRequirement'
                            TargetResources.ModifiedProperties.NewValue|startswith: "State"
                            TargetResources.ModifiedProperties|contains: "test"
                        condition: selection
                """
            )
        )
        == [
            'norm_id="AzureLogAnalytics" event_type="SigninLogs" target_modified_property=\'*"displayname": "StrongAuthenticationRequirement"*\' target_modified_property=\'*"newvalue": "State*"*\' target_modified_property="*test*"'
        ]
    )
