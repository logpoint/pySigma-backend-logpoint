# pySigma Logpoint Backend
![Tests](https://github.com/logpoint/pySigma-backend-logpoint/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/logpoint/pySigma-backend-logpoint/main/coverage-badge.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## Overview
This is the Logpoint backend for pySigma. It provides the package `sigma.backends.logpoint` with the `Logpoint` class.
Further, it contains the processing pipieline `sigma.pipelines.logpoint`, which performs field mapping and error handling.

The `sigma.pipelines.logpoint module` includes the following processing pipelines:

* `logpoint_windows`: This pipeline is designed to convert Sigma rules into queries specifically tailored for the Windows event logging format used by Logpoint.

## Rule Support
The Logpoint backend supports the following log sources/rule types:

- **Windows Sysmon**
- **Windows**
- **Azure**
- **M365**

## Usage example

### Sigma CLI

#### Requirements

1. To use Sigma CLI (the Sigma Rule Converter) and its underlying library, ensure you have Python version 3.8 or higher installed.
2. Install dependent **pysigma** verison 0.11.23. Installing other versions may output errors.

```bash
pip3 install pysigma==0.11.23
```

3. Install **sigma-cli**, command line tool for sigma rule conversion
```bash
pip3 install sigma-cli
```

4. After installing Sigma CLI, you need to add the **Logpoint backend plugin**. Choose one of the following methods:

```bash
sigma plugin install logpoint
```
**OR**

```bash
pip3 install pysigma-backend-logpoint
```

#### Converting Sigma Rules
Once the packages are successfully installed, you can convert Sigma rules into Logpoint queries using the command below. For example, to convert the
[Suspicious Process Masquerading As SvcHost.EXE](https://github.com/SigmaHQ/sigma/blob/598d29f811c1859ba18e05b8c419cc94410c9a55/rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml)

```bash
sigma convert -t logpoint -p logpoint_windows rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml
```
**Output**

```bash
╭─ubuntu@ubuntu
╰─$ sigma convert -t logpoint -p logpoint_windows rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml
Parsing Sigma rules  [####################################]  100%
label="Create" label="Process" "process"="*\svchost.exe" - ("process" IN ["C:\Windows\System32\svchost.exe", "C:\Windows\SysWOW64\svchost.exe"] OR file="svchost.exe")
```

## Limitations and Constraints
This backend is in its preliminary stage, which means there may be issues with query conversion from uncommon log types and it does not yet support conversion from all log sources covered by Sigma. Attempting to convert such rule types may result in an error.


This backend is currently maintained by Logpoint, with contributions from the following individuals:
* [Swachchhanda Shrawan Poudel](https://github.com/swachchhanda000/)
* [Surya Majhi](https://github.com/suryamajhi)

## Report Issues

If you encounter any issues, please don't hesitate to [open a new issue](https://github.com/logpoint/pySigma-backend-logpoint/issues/new).
