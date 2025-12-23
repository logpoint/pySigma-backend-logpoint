import re
from typing import Dict, Union, List

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    FieldFunctionTransformation,
)

from sigma.pipelines.logpoint.logpoint_mapping import (
    logpoint_linux_auditd_mapping,
    logpoint_linux_common_taxonomy,
)


def to_snake_case(field: str) -> str:
    """Convert field name to snake_case."""
    if not field:
        return field

    words = re.findall(r"([a-z0-9]+|[A-Z][a-z0-9]+|[A-Z0-9]+)", field)
    if len(words) > 1:
        return "_".join(words).lower()
    return words[0].lower() if words else field.lower()


def logpoint_linux_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Logpoint Linux",
        allowed_backends={"logpoint"},
        priority=20,
        items=[
            ProcessingItem(
                identifier="logpoint_linux_auditd_mapping",
                transformation=FieldMappingTransformation(
                    logpoint_linux_auditd_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(product="linux", service="auditd"),
                ],
            ),
            ProcessingItem(
                identifier="logpoint_linux_generic_mapping",
                transformation=FieldFunctionTransformation(
                    transform_func=to_snake_case, mapping=logpoint_linux_common_taxonomy
                ),
                rule_conditions=[
                    LogsourceCondition(product="linux"),
                ],
            ),
        ],
    )
