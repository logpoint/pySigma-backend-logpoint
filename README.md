# pySigma Logpoint Backend
![Tests](https://github.com/logpoint/pySigma-backend-logpoint/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/logpoint/pySigma-backend-logpoint/main/coverage-badge.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## Overview
This is the Logpoint backend for pySigma. It provides the package `sigma.backends.logpoint` with the `Logpoint` class.
Further, it contains the processing pipieline `sigma.pipelines.logpoint`, which performs field mapping and error handling.

## Rule Support
The Logpoint backend supports the following log sources/rule types:

- **Windows Sysmon**
- **Windows**

## Usage example

### Sigma CLI
--> Coming soon!!

### Stand-alone

#### Prerequisites

1. Ensure that you have Python installed (3.x is recommended).
2. Install **Poetry**, the package manager with following command
```bash
   curl -sSL https://install.python-poetry.org | python3 -
```
3. After installation, ensure Poetry is in your system’s PATH by adding the following line to your shell configuration (e.g., .bashrc, .zshrc, or .profile):
```bash
export PATH="$HOME/.local/bin:$PATH"
```
4. Navigate to your project directory and run the following command to install project dependencies:
```bash
cd pySigma-backend-logpoint
poetry install
```
5. Create a python script in the same directory with following content. 
The following example script, `test.py` can be used to convert your sigma rule of your choice to generate corresponding Logpoint Query.
[Suspicious Process Masquerading As SvcHost.EXE](https://github.com/SigmaHQ/sigma/blob/598d29f811c1859ba18e05b8c419cc94410c9a55/rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml)

```python
from sigma.backends.logpoint.logpoint import Logpoint
from sigma.pipelines.logpoint.windows import logpoint_windows_pipeline
from sigma.collection import SigmaCollection

# Place your sigma rule yml string here
logpoint_query = Logpoint(logpoint_windows_pipeline()).convert(
                SigmaCollection.from_yaml(
                    """
                    title: Suspicious Process Masquerading As SvcHost.EXE
                    id: be58d2e2-06c8-4f58-b666-b99f6dc3b6cd
                    related:
                        - id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
                        type: similar
                        - id: e4a6b256-3e47-40fc-89d2-7a477edd6915
                        type: similar
                    status: experimental
                    description: |
                        Detects a suspicious process that is masquerading as the legitimate "svchost.exe" by naming its binary "svchost.exe" and executing from an uncommon location.
                        Adversaries often disguise their malicious binaries by naming them after legitimate system processes like "svchost.exe" to evade detection.
                    references:
                        - https://tria.ge/240731-jh4crsycnb/behavioral2
                        - https://redcanary.com/blog/threat-detection/process-masquerading/
                    author: Swachchhanda Shrawan Poudel
                    date: 2024-08-07
                    tags:
                        - attack.defense-evasion
                        - attack.t1036.005
                    logsource:
                        category: process_creation
                        product: windows
                    detection:
                        selection:
                            Image|endswith: '\svchost.exe'
                        filter_main_img_location:
                            Image:
                                - 'C:\Windows\System32\svchost.exe'
                                - 'C:\Windows\SysWOW64\svchost.exe'
                        filter_main_ofn:
                            OriginalFileName: 'svchost.exe'
                        condition: selection and not 1 of filter_main_*
                    falsepositives:
                        - Unlikely
                    level: high
                    """
                )
            )

print(logpoint_query[0])
```

6.  Running the python file
```bash
poetry run python3 test.py

>> label="Create" label="Process" "process"="*\svchost.exe" - ("process" in ["C:\Windows\System32\svchost.exe", "C:\Windows\SysWOW64\svchost.exe"] or file="svchost.exe")
```

## Limitations and Constraints
This backend is in its preliminary stage, which means there may be issues with query conversion from uncommon log types and it does not yet support conversion from all log sources covered by Sigma. Attempting to convert such rule types may result in an error.


This backend is currently maintained by Logpoint, with contributions from the following individuals:
* [Swachchhanda Shrawan Poudel](https://github.com/swachchhanda000/)
* [Surya Majhi](https://github.com/suryamajhi)

## Report Issues

If you encounter any issues, please don't hesitate to [open a new issue](https://github.com/logpoint/pySigma-backend-logpoint/issues/new).
