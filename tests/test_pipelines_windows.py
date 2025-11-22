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

    assert rule.fields == ["event_id", "test_field"]


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
        == [
            'label="Create" label="Process" command="test" file="test.exe" "process"="*\cloudflared.exe"'
        ]
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
        == [
            'label="Load" label="Driver" command="test" file="test.exe" image="*\cloudflared.exe"'
        ]
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
        == [
            'event_id IN [12, 13, 14] norm_id="WindowsSysmon" target_object="*System\CurrentControlSet\Services\VSS*" "process"="*esentutl.exe" -target_object="*System\CurrentControlSet\Services\VSS\Start*"'
        ]
    )


def test_logpoint_windows_hashes():
    assert (
        Logpoint(logpoint_windows_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: PUA - Process Hacker Execution
                    date: 2022-10-10
                    modified: 2023-12-11
                    tags:
                        - attack.defense-evasion
                        - attack.discovery
                        - attack.persistence
                        - attack.privilege-escalation
                        - attack.t1622
                        - attack.t1564
                        - attack.t1543
                    logsource:
                        category: process_creation
                        product: windows
                    detection:
                        selection_images:
                            Image|endswith: 'undll32.exe'
                        selection_hashes:
                            Hashes:
                                - 'MD5=68F9B52895F4D34E74112F3129B3B00D'
                                - 'SHA1=A0BDFAC3CE1880B32FF9B696458327CE352E3B1D'
                                - 'SHA256=D4A0FE56316A2C45B9BA9AC1005363309A3EDC7ACF9E4DF64D326A0FF273E80F'
                                - 'IMPHASH=3695333C60DEDECDCAFF1590409AA462'
                        condition: 1 of selection_*
                    falsepositives:
                        - While sometimes 'Process Hacker is used by legitimate administrators, the execution of Process Hacker must be investigated and allowed on a case by case basis
                    level: medium
                """
            )
        )
        == [
            'label="Create" label="Process" "process"="*undll32.exe" OR hash="68F9B52895F4D34E74112F3129B3B00D" OR '
            'hash_sha1="A0BDFAC3CE1880B32FF9B696458327CE352E3B1D" OR '
            'hash_sha256="D4A0FE56316A2C45B9BA9AC1005363309A3EDC7ACF9E4DF64D326A0FF273E80F" OR '
            'hash_import="3695333C60DEDECDCAFF1590409AA462"'
        ]
    )


def test_logpoint_windows_hashes_duplicates():
    assert (
        Logpoint(logpoint_windows_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: PUA - System Informer Execution
                    id: 5722dff1-4bdd-4949-86ab-fbaf707e767a
                    date: 2023-05-08
                    logsource:
                        category: process_creation
                        product: windows
                    detection:
                        selection_hashes:
                            Hashes|contains:
                                # Note: add other hashes as needed
                                # 3.0.11077.6550
                                - 'MD5=19426363A37C03C3ED6FEDF57B6696EC'
                                - 'SHA1=8B12C6DA8FAC0D5E8AB999C31E5EA04AF32D53DC'
                                - 'SHA256=8EE9D84DE50803545937A63C686822388A3338497CDDB660D5D69CF68B68F287'
                                - 'IMPHASH=B68908ADAEB5D662F87F2528AF318F12'
                        selection_hash_values:
                            - md5: '19426363A37C03C3ED6FEDF57B6696EC'
                            - sha1: '8B12C6DA8FAC0D5E8AB999C31E5EA04AF32D53DC'
                            - sha256: '8EE9D84DE50803545937A63C686822388A3338497CDDB660D5D69CF68B68F287'
                            - Imphash: 'B68908ADAEB5D662F87F2528AF318F12'
                        condition: 1 of selection_*
                    falsepositives:
                        - System Informer is regularly used legitimately by system administrators or developers. Apply additional filters accordingly
                    level: medium
                """
            )
        )
        == [
            'label="Create" label="Process" hash="19426363A37C03C3ED6FEDF57B6696EC*" OR '
            'hash_sha1="8B12C6DA8FAC0D5E8AB999C31E5EA04AF32D53DC*" OR '
            'hash_sha256="8EE9D84DE50803545937A63C686822388A3338497CDDB660D5D69CF68B68F287*" '
            'OR hash_import="B68908ADAEB5D662F87F2528AF318F12*" OR '
            'hash="19426363A37C03C3ED6FEDF57B6696EC" OR '
            'hash_sha1="8B12C6DA8FAC0D5E8AB999C31E5EA04AF32D53DC" OR '
            'hash_sha256="8EE9D84DE50803545937A63C686822388A3338497CDDB660D5D69CF68B68F287" '
            'OR hash_import="B68908ADAEB5D662F87F2528AF318F12"'
        ]
    )
