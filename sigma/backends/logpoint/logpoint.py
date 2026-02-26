import re
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
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCompareExpression,
    SpecialChars,
    SigmaString,
    Placeholder,
)


class LogpointDeferredRegularExpression(DeferredTextQueryExpression):
    field_count = {}
    default_field = "msg"
    operators = {True: "!=", False: "="}

    def __init__(self, state, field, arg):
        self.add_field(field)
        field_condition = self.get_field_condition(field)
        field_match = self.get_field_match(field)
        self.template = "process regex(\"(?P<{field_match}>{{value}})\", {{field}})\n| process eval(\"{field_condition}=case(isnotnull({field_match}) -> 'true', 'false')\")".format(
            field_match=field_match, field_condition=field_condition
        )
        super().__init__(state, field, arg)

    @classmethod
    def add_field(cls, field):
        cls.field_count[field] = (
            cls.field_count.get(field, 0) + 1
        )  # increment the field count

    @classmethod
    def get_field_suffix(cls, field):
        index_suffix = cls.field_count.get(field, "")
        if index_suffix == 1:
            index_suffix = ""
        return index_suffix

    @classmethod
    def construct_field_variable(cls, field, variable):
        index_suffix = cls.get_field_suffix(field)
        return f"{field}_{variable}{index_suffix}"

    @classmethod
    def get_field_match(cls, field):
        return cls.construct_field_variable(field, "match")

    @classmethod
    def get_field_condition(cls, field):
        return cls.construct_field_variable(field, "condition")

    @classmethod
    def reset(cls):
        cls.field_count = {}


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

    empty_or_expression: ClassVar[Optional[str]] = ""
    empty_and_expression: ClassVar[Optional[str]] = ""

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
    deferred_start: ClassVar[str] = "| "
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
        LogpointDeferredRegularExpression(
            state,
            cond.field,
            super().convert_condition_field_eq_val_re(cond, state),
        ).postprocess(None, cond)

        cond_true = ConditionFieldEqualsValueExpression(
            LogpointDeferredRegularExpression.get_field_condition(cond.field),
            SigmaString("true"),
        )
        return super().convert_condition_field_eq_val_str(cond_true, state)

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query.
        Overwrite cause we don't want to escape double quote character as we can quote the whole value with single quote.
        """
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
        if isinstance(query, DeferredQueryExpression):
            query = self.deferred_only_query

        if state.has_deferred():
            deferred_regex_expressions = []
            remaining_deferred = []

            for deferred_expression in state.deferred:
                if isinstance(deferred_expression, LogpointDeferredRegularExpression):
                    deferred_regex_expressions.append(
                        deferred_expression.finalize_expression()
                    )
                else:
                    remaining_deferred.append(deferred_expression)

            if deferred_regex_expressions:
                LogpointDeferredRegularExpression.reset()
                state.deferred[:] = remaining_deferred
                query = (
                    self.deferred_start
                    + self.deferred_separator.join(deferred_regex_expressions)
                    + "\n| search "
                    + query
                )

        return super().finish_query(rule, query, state)
