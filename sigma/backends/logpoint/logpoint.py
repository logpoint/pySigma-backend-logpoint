import re
from collections import ChainMap
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any

from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionType,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import (
    DeferredQueryExpression,
    DeferredTextQueryExpression,
)
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule, SigmaDetectionItem, SigmaDetection
from sigma.types import (
    SigmaCompareExpression,
    SpecialChars,
    SigmaString,
    Placeholder,
)


class LogpointDeferredRegularExpression(DeferredTextQueryExpression):
    # Group capturing in regex process command adds the new field in event if successful.
    template = 'process regex("(?P<re{id}>{value})", {field})'
    default_field = "msg"

    def finalize_expression(self, id) -> str:
        # id for incremental assignment of the field on prefix re. The new fields will be re1, re2, re3, ...
        return self.template.format(id=id, field=self.field, value=self.value)


class Logpoint(TextQueryBackend):
    """
    Logpoint search query language backend.
    """

    # A descriptive name of the backend
    name: ClassVar[str] = "Logpoint Query Language"
    # Output formats provided by the backend as name -> description mapping.
    # The name should match to finalize_output_<name>.
    formats: ClassVar[Dict[str, str]] = {"default": "Plain Logpoint search queries."}
    # Does the backend requires that a processing pipeline is provided?
    requires_pipeline: ClassVar[bool] = True

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )

    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[str] = "({expr})"
    # parenthesize = True

    token_separator = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = " "
    not_token: ClassVar[str] = "-"
    eq_token: ClassVar[str] = "="

    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^[\w.]+$")

    str_quote: ClassVar[str] = '"'
    str_quote_pattern: ClassVar[Pattern] = re.compile(r"^$|.*")
    str_quote_pattern_negation: ClassVar[bool] = False
    # Escaping character for special characters inside string
    # escape_char: ClassVar[str] = "\\"

    # Character used as multi-character wildcard
    wildcard_multi: ClassVar[str] = "*"
    # Character used as single-character wildcard
    wildcard_single: ClassVar[str] = "?"

    re_expression: ClassVar[str] = "{regex}"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = ""

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    # Mapping between CompareOperators elements and strings used as replacement
    # for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = "{field}!=*"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    # Convert OR as in-expression
    convert_or_as_in: ClassVar[bool] = True

    # Values in list can contain wildcards. If set to False (default)
    # only plain values are converted into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = True
    # Expression for field in list of values as format string with
    # placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "{field} {op} [{list}]"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[Optional[str]] = "IN"

    # List element separator
    list_separator: ClassVar[str] = ", "

    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = (
        "{value}"  # str values are already wrapped with quotes
    )
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = (
        '"{value}"'  # wrap num values in quotes
    )

    # String used as separator between main query and deferred parts
    deferred_start: ClassVar[str] = " \n| "
    # String used to join multiple deferred query parts
    deferred_separator: ClassVar[str] = " \n| "
    # String used as query if final query only contains deferred expression
    deferred_only_query: ClassVar[str] = ""

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        output_settings: Dict = {},
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.logpoint_keywords: List[str] = [
            "process",
            "filter",
            "search",
            "chart",
            "and",
            "in",
            "or",
        ]

    def convert_condition_field_eq_val_re(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: "sigma.conversion.state.ConversionState",
    ) -> ConditionItem:
        """Defer regular expression matching to pipelined regex command after main search expression."""
        # TODO: Think about solving when all regex expr are provided either in OR or AND.
        return LogpointDeferredRegularExpression(
            state,
            self.escape_and_quote_field(cond.field),
            super().convert_condition_field_eq_val_re(cond, state),
        ).postprocess(None, cond)

    def escape_and_quote_field(self, field_name: str) -> str:
        """
        Fields are not escaped in Logpoint Query Language.

        Quote field name with field_quote if field_quote_pattern (doesn't) matches the original
        (unescaped) field name. If field_quote_pattern_negation is set to True (default) the pattern matching
        result is negated, which is the default behavior. In this case the field name is quoted if
        the pattern doesn't matches.
        """

        escaped_field_name = field_name

        if self.field_quote is not None:  # Field quoting
            if self.field_quote_pattern is not None:  # Match field quote pattern...
                quote = bool(self.field_quote_pattern.match(escaped_field_name))
                if (
                    self.field_quote_pattern_negation
                ):  # ...negate result of matching, if requested...
                    quote = not quote
            else:
                quote = True

            if (
                escaped_field_name.lower() in self.logpoint_keywords
            ):  # quote if field is logpoint's keyword
                quote = True

            if quote:  # ...and quote if pattern (doesn't) matches
                return self.field_quote + escaped_field_name + self.field_quote
        return escaped_field_name

    def quote_string(self, s: str) -> str:
        """Put quotes around string."""
        if '"' in s:
            return "'" + s + "'"
        return self.str_quote + s + self.str_quote

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""
        converted = s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.add_escaped,
            self.filter_chars,
        )
        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        else:
            return converted

    def construct_sigma_string_for_json_substring(
        self,
        sigma_tuple: List[Union[str, SpecialChars, Placeholder]],
        required_fields: List[str],
    ) -> SigmaString:
        """Manually add wildcard characters for complex json objects like modified properties for now.
        modifiedProperties.newValue = "test"
        Result: modified_properties = '*"newValue": "test"*'
        """
        if required_fields:
            sigma_tuple.append('"')
            sigma_tuple.append(SpecialChars.WILDCARD_MULTI)
            sigma_tuple.insert(0, '"')

            value_field = required_fields[-1]
            sigma_tuple.insert(0, " ")
            sigma_tuple.insert(0, ":")
            sigma_tuple.insert(0, '"')
            sigma_tuple.insert(0, value_field)
            sigma_tuple.insert(0, '"')
            sigma_tuple.insert(0, SpecialChars.WILDCARD_MULTI)

            remaining_fields = required_fields[:-1]
            remaining_fields.reverse()
            for field in remaining_fields:
                sigma_tuple.insert(0, '"')
                sigma_tuple.insert(0, field)
                sigma_tuple.insert(0, '"')
                sigma_tuple.insert(0, SpecialChars.WILDCARD_MULTI)

        sigma_string = SigmaString()
        sigma_string.s = tuple(sigma_tuple)
        return sigma_string

    def modify_condition_from_json_value_construction(
        self, cond: ConditionFieldEqualsValueExpression
    ):
        if cond.field and "modifiedproperties" in cond.field.lower():
            field: str = cond.field.lower()
            field = field.replace("{}", "")  # Removing {} from the field
            json_fields: List[str] = field.split(".")
            required_fields: List[str] = json_fields[
                json_fields.index("modifiedproperties") + 1 :
            ]  # fields that are inside of json

            cond.field = json_fields[0]
            cond.value = self.construct_sigma_string_for_json_substring(
                list(cond.value.s), required_fields
            )

    def convert_condition(self, cond: ConditionType, state: ConversionState) -> Any:
        if (
            isinstance(cond, ConditionOR)
            or isinstance(cond, ConditionAND)
            or isinstance(cond, ConditionNOT)
        ):
            [
                self.modify_condition_from_json_value_construction(arg)
                for arg in cond.args
                if isinstance(arg, ConditionFieldEqualsValueExpression)
            ]
        elif isinstance(cond, ConditionFieldEqualsValueExpression):
            self.modify_condition_from_json_value_construction(cond)
        return super().convert_condition(cond, state)

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if (
                arg.__class__ in self.precedence
            ):  # group if AND or OR condition is negated
                return self.not_token + self.convert_condition_group(arg, state)
            expr = self.convert_condition(arg, state)
            if isinstance(
                expr, DeferredQueryExpression
            ):  # negate deferred expression and return for later resolution in the calling context
                return expr.negate()
            return self.not_token + expr  # convert negated expression to string
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def _recursively_substitute_sigma_items(self, detection_item: Union[SigmaDetection, SigmaDetectionItem], orig_field: str, new_field: str):
        if (
                isinstance(detection_item, SigmaDetectionItem)
                and orig_field == detection_item.field
        ):
            detection_item.field = new_field
            # Overriding the regex modifier
            detection_item.modifiers = []
            # On successful regex match, a new field is add with any value. So re1=* would suffice and filter the results.
            detection_item.value = [SigmaString("*")]

        elif isinstance(detection_item, SigmaDetection):
            for d in detection_item.detection_items:
                self._recursively_substitute_sigma_items(d, orig_field, new_field)
        else:
            assert "Should not be here"

    def finish_query(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: Any,
        state: ConversionState,
    ) -> Any:
        """
        Finish query by appending deferred query parts to the main conversion result as specified
        with deferred_start and deferred_separator.
        """
        conversion_state = ChainMap(state.processing_state, self.state_defaults)  # type: ignore

        if state.has_deferred():
            # TODO: For now only worry about deferred regular expression. Need to generalize later.
            if self.deferred_start is None or self.deferred_separator is None:
                raise NotImplementedError(
                    "Deferred query parts are not supported by the backend."
                )
            deferred_fields: List[str] = [
                deferred_expression.field for deferred_expression in state.deferred
            ]
            deferred_fields_inclusion = [f"{field}=*" for field in deferred_fields]
            if isinstance(query, DeferredQueryExpression):
                query = self.deferred_only_query + " OR ".join(
                    deferred_fields_inclusion
                )
            else:
                query = (
                    "(" + query + ")" + " OR " + " OR ".join(deferred_fields_inclusion)
                )

            query = (
                self.query_expression.format(
                    query=query,
                    rule=rule,
                    state=conversion_state,
                )
                + self.deferred_start
                + self.deferred_separator.join(
                    (
                        deferred_expression.finalize_expression(i + 1)
                        for i, deferred_expression in enumerate(state.deferred)
                    )
                )
            )

            # Modify the rule to replace the original field with new field processed by regex process command.
            for i, orig_field in enumerate(deferred_fields):
                new_field = (
                    f"re{i + 1}"  # Only regular expressions are deferred at this point.
                )

                for cond, sigma_detection in rule.detection.detections.items():
                    for detection_item in sigma_detection.detection_items:
                        self._recursively_substitute_sigma_items(detection_item, orig_field, new_field)

            # Re-convert the rule again and append at the end with search expression
            query += " \n| search " + self.convert_rule(rule)[0]
        else:
            query = self.query_expression.format(
                query=query,
                rule=rule,
                state=conversion_state,
            )

        return query
