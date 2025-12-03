from sigma.backends.logpoint.logpoint import Logpoint
from sigma.pipelines.logpoint.linux import logpoint_linux_pipeline
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def test_logpoint_linux_auditd():
    assert (
        Logpoint(logpoint_linux_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: linux
                        service: auditd
                    detection:
                        sel:
                            type: EXECVE
                            proctitle: /usr/bin/test
                            auid: 1000
                        condition: sel
                """
            )
        )
        == ['event_type="EXECVE" command="/usr/bin/test" user_id=1000']
    )


def test_logpoint_linux_generic():
    assert (
        Logpoint(logpoint_linux_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: linux
                        category: process_creation
                    detection:
                        sel:
                            Image: /usr/bin/test
                            CommandLine: test arg
                        condition: sel
                """
            )
        )
        == ['"process"="/usr/bin/test" command="test arg"']
    )


def test_logpoint_linux_snake_case():
    assert (
        Logpoint(logpoint_linux_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                    title: Test
                    status: test
                    logsource:
                        product: linux
                    detection:
                        sel:
                            SomeField: test
                        condition: sel
                """
            )
        )
        == ['some_field="test"']
    )
