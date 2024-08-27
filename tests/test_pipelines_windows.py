from sigma.backends.logpoint.logpoint import Logpoint
from sigma.pipelines.logpoint.windows import logpoint_windows_pipeline
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def test_logpoint_windows():
    assert (
            Logpoint(logpoint_windows_pipeline()).convert(
                SigmaCollection.from_yaml(
                    """
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        service: security
                    detection:
                        sel:
                            EventID: 123
                            Image: test.exe
                            TestField: test
                            TargetObject: obj
                        condition: sel
                """
                )
            )
            == [
                'norm_id="WinServer" event_id=123 image="test.exe" test_field="test" target_object="obj"'
            ]
    )


def test_logpoint_windows_fields():
    rule = logpoint_windows_pipeline().apply(
        SigmaRule.from_yaml(
            """
                title: Test
                status: test
                logsource:
                    product: windows
                    service: security
                detection:
                    sel:
                        EventID: 123
                        Image: test.exe
                        TestField: test
                    condition: sel
                fields:
                    - EventID
                    - TestField
            """
        )
    )

    assert rule.fields == ['event_id', 'test_field']


def test_logpoint_windows_variable_mapping():
    assert (
            Logpoint(logpoint_windows_pipeline()).convert(
                SigmaCollection.from_yaml(
                    """
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        category: process_creation
                    detection:
                        sel:
                            CommandLine: test
                            OriginalFileName: test.exe
                        condition: sel
                """
                )
            )
            == ['label="Create" label="Process" command="test" file="test.exe"']
    )


def test_logpoint_windows_variable_mapping_process_creation():
    assert (
            Logpoint(logpoint_windows_pipeline()).convert(
                SigmaCollection.from_yaml(
                    """
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        category: process_creation
                    detection:
                        sel:
                            CommandLine: test
                            OriginalFileName: test.exe
                            Image|endswith:
                                - '\cloudflared.exe'
                        condition: sel
                """
                )
            )
            == ['label="Create" label="Process" command="test" file="test.exe" "process"="*\cloudflared.exe"']
    )


def test_logpoint_windows_variable_mapping_driver_loaded():
    assert (
            Logpoint(logpoint_windows_pipeline()).convert(
                SigmaCollection.from_yaml(
                    """
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        category: driver_load
                    detection:
                        sel:
                            CommandLine: test
                            OriginalFileName: test.exe
                            ImageLoaded|endswith:
                                - '\cloudflared.exe'
                        condition: sel
                """
                )
            )
            == ['label="Load" label="Driver" command="test" file="test.exe" image="*\cloudflared.exe"']
    )

def test_logpoint_windows_variable_mapping_registry_event():
    assert (
            Logpoint(logpoint_windows_pipeline()).convert(
                SigmaCollection.from_yaml(
                    """
                    title: Esentutl Volume Shadow Copy Service Keys
                    id: 5aad0995-46ab-41bd-a9ff-724f41114971
                    status: test
                    description: Detects the volume shadow copy service initialization and processing via esentutl. Registry keys such as HKLM\\System\\CurrentControlSet\\Services\\VSS\\Diag\\VolSnap\\Volume are captured.
                    references:
                        - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy
                    author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
                    date: 2020/10/20
                    modified: 2022/12/25
                    tags:
                        - attack.credential_access
                        - attack.t1003.002
                    logsource:
                        category: registry_event
                        product: windows
                    detection:
                        selection:
                            TargetObject|contains: 'System\CurrentControlSet\Services\VSS'
                            Image|endswith: 'esentutl.exe' # limit esentutl as in references, too many FP to filter
                        filter:
                            TargetObject|contains: 'System\CurrentControlSet\Services\VSS\Start'
                        condition: selection and not filter
                    falsepositives:
                        - Unknown
                    level: high
                """
                )
            )
            == ['event_id IN [12, 13, 14] norm_id="WindowsSysmon" target_object="*System\CurrentControlSet\Services\VSS*" "process"="*esentutl.exe" - target_object="*System\CurrentControlSet\Services\VSS\Start*"']
    )

