from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.logpoint import Logpoint
from sigma.pipelines.logpoint import logpoint_defer_contains, logpoint_windows_pipeline


def test_logpoint_defer_contains():
    assert (
        Logpoint(logpoint_defer_contains()).convert(
            SigmaCollection.from_yaml(
                r"""
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        service: security
                    detection:
                        sel:
                            fieldA|contains:
                                - abc
                                - xyz
                        condition: sel
                """
            )
        )
        == [
            '''
| process eval("fieldA_contains=issubstr('abc', fieldA) || issubstr('xyz', fieldA)")
| search fieldA_contains="true"'''
        ]
    )


def test_logpoint_defer_contains_wildcard():
    assert (
        Logpoint(logpoint_defer_contains()).convert(
            SigmaCollection.from_yaml(
                r"""
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        service: security
                    detection:
                        sel:
                            fieldA|contains:
                                - ab*c
                                - ab?c
                                - xyz
                        condition: sel
                """
            )
        )
        == [
            '''
| process eval("fieldA_contains=match(fieldA, '(?i)ab.*c') || match(fieldA, '(?i)ab.c') || issubstr('xyz', fieldA)")
| search fieldA_contains="true"'''
        ]
    )


def test_logpoint_defer_contains_wildcard_escape():
    assert (
        Logpoint(logpoint_defer_contains()).convert(
            SigmaCollection.from_yaml(
                r"""
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        service: security
                    detection:
                        sel:
                            fieldA|contains:
                                - ab\*c
                                - ab\?c
                                - xyz
                        condition: sel
                """
            )
        )
        == [
            '''
| process eval("fieldA_contains=issubstr('ab*c', fieldA) || issubstr('ab?c', fieldA) || issubstr('xyz', fieldA)")
| search fieldA_contains="true"'''
        ]
    )


def test_logpoint_defer_contains_wildcard_and_wildcard_escape():
    assert (
        Logpoint(logpoint_defer_contains()).convert(
            SigmaCollection.from_yaml(
                r"""
                    title: Test
                    status: test
                    logsource:
                        product: windows
                        service: security
                    detection:
                        sel:
                            fieldA|contains:
                                - ab\**c
                                - ab\?c*d
                                - xyz
                        condition: sel
                """
            )
        )
        == [
            '''
| process eval("fieldA_contains=match(fieldA, '(?i)ab\*.*c') || match(fieldA, '(?i)ab\?c.*d') || issubstr('xyz', fieldA)")
| search fieldA_contains="true"'''
        ]
    )


def test_logpoint_defers_contain_real_example():
    resolver = ProcessingPipelineResolver(
        {
            "defer_contains": logpoint_defer_contains(),
            "window": logpoint_windows_pipeline(),
        }
    )
    assert (
        Logpoint(resolver.resolve(["defer_contains", "window"])).convert(
            SigmaCollection.from_yaml(
                r"""
title: Suspicious SYSTEM User Process Creation
id: 2617e7ed-adb7-40ba-b0f3-8f9945fe6c09
status: test
description: Detects a suspicious process creation as SYSTEM user (suspicious program or command line parameter)
references:
    - Internal Research
    - https://tools.thehacker.recipes/mimikatz/modules
author: Florian Roth (rule), David ANDRE (additional keywords)
date: 2021-12-20
modified: 2022-04-27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        IntegrityLevel: System
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    selection_special:
        - Image|endswith:
            - '\calc.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\hh.exe'
            - '\mshta.exe'
            - '\forfiles.exe'
            - '\ping.exe'
        - CommandLine|contains:
            # - 'sc stop ' # stops a system service # causes FPs
            - ' -NoP '  # Often used in malicious PowerShell commands
            - ' -W Hidden '  # Often used in malicious PowerShell commands
            - ' -decode '  # Used with certutil
            - ' /decode '  # Used with certutil
            - ' /urlcache '  # Used with certutil
            - ' -urlcache '  # Used with certutil
            - ' -e\* JAB'  # PowerShell encoded commands
            - ' -e* SUVYI'  # PowerShell encoded commands
            - ' -e* SQBFAFgA'  # PowerShell encoded commands
            - ' -e* aWV4I'  # PowerShell encoded commands
            - ' -e* IAB'  # PowerShell ncoded commands
            - ' -e* PAA'  # PowerShell encoded commands
            - ' -e* aQBlAHgA'  # PowerShell encoded commands
            - 'vssadmin delete shadows'  # Ransomware
            - 'reg SAVE HKLM'  # save registry SAM - syskey extraction
            - ' -ma '  # ProcDump
            - 'Microsoft\Windows\CurrentVersion\Run'  # Run key in command line - often in combination with REG ADD
            - '.downloadstring('  # PowerShell download command
            - '.downloadfile('  # PowerShell download command
            - ' /ticket:'  # Rubeus
            - 'dpapi::'     #Mimikatz
            - 'event::clear'        #Mimikatz
            - 'event::drop'     #Mimikatz
            - 'id::modify'      #Mimikatz
            - 'kerberos::'       #Mimikatz
            - 'lsadump::'      #Mimikatz
            - 'misc::'     #Mimikatz
            - 'privilege::'       #Mimikatz
            - 'rpc::'      #Mimikatz
            - 'sekurlsa::'       #Mimikatz
            - 'sid::'        #Mimikatz
            - 'token::'      #Mimikatz
            - 'vault::cred'     #Mimikatz
            - 'vault::list'     #Mimikatz
            - ' p::d '  # Mimikatz
            - ';iex('  # PowerShell IEX
            - 'MiniDump'  # Process dumping method apart from procdump
            - 'net user '
    condition: all of selection*
falsepositives:
    - Administrative activity
    - Scripts and administrative tools used in the monitored environment
    - Monitoring activity
level: high
                """
            )
        )
        == [
            r'''label="Process" label="Create"
| process eval("user_contains=issubstr('AUTHORI', user) || issubstr('AUTORI', user)") 
| process eval("command_contains=issubstr(' -NoP ', command) || issubstr(' -W Hidden ', command) || issubstr(' -decode ', command) || issubstr(' /decode ', command) || issubstr(' /urlcache ', command) || issubstr(' -urlcache ', command) || issubstr(' -e* JAB', command) || match(command, '(?i) -e.* SUVYI') || match(command, '(?i) -e.* SQBFAFgA') || match(command, '(?i) -e.* aWV4I') || match(command, '(?i) -e.* IAB') || match(command, '(?i) -e.* PAA') || match(command, '(?i) -e.* aQBlAHgA') || issubstr('vssadmin delete shadows', command) || issubstr('reg SAVE HKLM', command) || issubstr(' -ma ', command) || issubstr('Microsoft\Windows\CurrentVersion\Run', command) || issubstr('.downloadstring(', command) || issubstr('.downloadfile(', command) || issubstr(' /ticket:', command) || issubstr('dpapi::', command) || issubstr('event::clear', command) || issubstr('event::drop', command) || issubstr('id::modify', command) || issubstr('kerberos::', command) || issubstr('lsadump::', command) || issubstr('misc::', command) || issubstr('privilege::', command) || issubstr('rpc::', command) || issubstr('sekurlsa::', command) || issubstr('sid::', command) || issubstr('token::', command) || issubstr('vault::cred', command) || issubstr('vault::list', command) || issubstr(' p::d ', command) || issubstr(';iex(', command) || issubstr('MiniDump', command) || issubstr('net user ', command)")
| search integrity_level="System" user_contains="true" "process" IN ["*\calc.exe", "*\wscript.exe", "*\cscript.exe", "*\hh.exe", "*\mshta.exe", "*\forfiles.exe", "*\ping.exe"] OR command_contains="true"'''
        ]
    )


def test_logpoint_defers_contain_real_example_2():
    resolver = ProcessingPipelineResolver(
        {
            "defer_contains": logpoint_defer_contains(),
            "window": logpoint_windows_pipeline(),
        }
    )
    assert (
        Logpoint(resolver.resolve(["defer_contains", "window"])).convert(
            SigmaCollection.from_yaml(
                r"""
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
                            TargetObject|contains: 
                                - 'System\CurrentControlSet\Services\VSS'
                                - 'e* JAB'
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
            r'''norm_id="WindowsSysmon" event_id IN [12, 13, 14]
| process eval("target_object_contains=issubstr('System\CurrentControlSet\Services\VSS', target_object) || match(target_object, '(?i)e.* JAB')")
| search target_object_contains="true" "process"="*esentutl.exe" -target_object="*System\CurrentControlSet\Services\VSS\Start*"'''
        ]
    )
