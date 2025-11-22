from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
import pytest
from sigma.backends.logpoint import Logpoint
from sigma.collection import SigmaCollection


@pytest.fixture()
def logpoint_backend():
    return Logpoint()


def test_logpoint_and_expression(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )

    assert logpoint_backend.convert(rule) == ['fieldA="valueA" fieldB="valueB"']


def test_logpoint_or_expression(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
    )
    assert logpoint_backend.convert(rule) == ['fieldA="valueA" OR fieldB="valueB"']


def test_logpoint_and_or_expression(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == [
        'fieldA IN ["valueA1", "valueA2"] fieldB IN ["valueB1", "valueB2"]'
    ]


def test_logpoint_or_and_expression(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
    )
    assert logpoint_backend.convert(rule) == [
        '(fieldA="valueA1" fieldB="valueB1") OR (fieldA="valueA2" fieldB="valueB2")'
    ]


def test_logpoint_in_expression(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == [
        'fieldA IN ["valueA", "valueB", "valueC*"]'
    ]


def test_logpoint_in_expression_empty_string(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - ''
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == ['fieldA IN ["valueA", ""]']


def test_logpoint_field_name_with_whitespace(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == ['"field name"="value"']


def test_logpoint_field_name_with_keywords(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    process: value
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == ['"process"="value"']


def test_logpoint_field_name_with_keywords_different_case(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Process: value
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == ['"Process"="value"']


def test_logpoint_not_filter_null_and(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and not filter_1 and not filter_2
        """
    )

    assert logpoint_backend.convert(rule) == ['FieldA="*valueA" -FieldB!=* -FieldB=""']


def test_logpoint_filter_null_and(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and filter_1 and not filter_2
        """
    )

    assert logpoint_backend.convert(rule) == ['FieldA="*valueA" FieldB!=* -FieldB=""']


def test_logpoint_not_filter_null_or(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and (not filter_1 or not filter_2)
        """
    )

    assert logpoint_backend.convert(rule) == [
        'FieldA="*valueA" -FieldB!=* OR -FieldB=""'
    ]


def test_logpoint_filter_null_or(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and (filter_1 or not filter_2)
        """
    )

    assert logpoint_backend.convert(rule) == [
        'FieldA="*valueA" FieldB!=* OR -FieldB=""'
    ]


def test_logpoint_filter_not_or_null(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and not 1 of filter_*
        """
    )

    assert logpoint_backend.convert(rule) == [
        'FieldA="*valueA" -(FieldB!=* OR FieldB="")'
    ]


def test_logpoint_filter_not(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                filter:
                    Field: null
                condition: not filter
        """
    )

    assert logpoint_backend.convert(rule) == ["-Field!=*"]


def test_logpoint_angle_brackets(logpoint_backend: Logpoint):
    """Test for DSL output with < or > in the values"""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection_cmd:
                    - OriginalFileName: 'Cmd.exe'
                    - Image|endswith: '\cmd.exe'
                selection_cli:
                    - CommandLine|contains: '<'
                    - CommandLine|contains: '>'
                condition: all of selection_*
        """
    )

    assert logpoint_backend.convert(rule) == [
        r'OriginalFileName="Cmd.exe" OR Image="*\cmd.exe" CommandLine IN ["*<*", "*>*"]'
    ]


def test_logpoint_cidr_query(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 
                        - 192.168.0.0/16
                        - 10.0.0.0/8
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == [
        'field IN ["192.168.*"] OR field IN ["10.*"] fieldB="foo" fieldC="bar"'
    ]


def test_logpoint_regex_query(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == [
        'fieldB="foo" | process regex("foo.*bar", fieldA, "filter=true")'
    ]


def test_logpoint_regex_query_escaped_input(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 127\.0\.0\.1:[1-9]\d{3}
                    fieldB: foo
                    fieldC|re: foo/bar
                condition: sel
        """
    )
    assert logpoint_backend.convert(rule) == [
        'fieldB="foo" | process regex("127\.0\.0\.1:[1-9]\d{3}", fieldA, "filter=true") | process regex("foo/bar", fieldC, "filter=true")'
    ]


def test_logpoint_contains_all(logpoint_backend: Logpoint):
    """Test for DSL output with < or > in the values"""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains|all:
                        - valueA
                        - valueB
                condition: sel
        """
    )

    assert logpoint_backend.convert(rule) == [
        r'''fieldA="*valueA*" fieldA="*valueB*"'''
    ]


def test_logpoint_double_quote_value(logpoint_backend: Logpoint):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: val"ueB
                condition: sel
        """
    )

    assert logpoint_backend.convert(rule) == ['fieldA="valueA" fieldB=\'val"ueB\'']
