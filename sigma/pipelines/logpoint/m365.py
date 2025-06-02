from sigma.processing.conditions import (
    LogsourceCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddConditionTransformation,
    FieldFunctionTransformation,
)

from sigma.pipelines.logpoint.logpoint_mapping import logpoint_m365_mapping


def m365_field_mapping(field: str):
    if field.lower().startswith("modifiedproperties"):
        return "modified_property." + field
    return field


def logpoint_m365_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Logpoint M365",
        allowed_backends={"logpoint"},
        priority=20,
        items=[
            ProcessingItem(
                identifier="logpoint_m365_taxonomy",
                transformation=FieldMappingTransformation(logpoint_m365_mapping),
                rule_conditions=[LogsourceCondition(product="m365")],
            ),
            ProcessingItem(
                identifier="logpoint_m365_threat_management",
                transformation=(
                    AddConditionTransformation({"category": "ThreatManagement"})
                ),
                rule_conditions=[
                    LogsourceCondition(product="m365", service="threat_management")
                ],
            ),
            ProcessingItem(
                identifier="logpoint_m365_norm_id_enrich",
                transformation=(AddConditionTransformation({"norm_id": "Office365"})),
                rule_conditions=[LogsourceCondition(product="m365")],
            ),
            ProcessingItem(
                identifier="logpoint_azure_activity_enrich",
                transformation=(
                    FieldFunctionTransformation(transform_func=m365_field_mapping)
                ),
                rule_conditions=[LogsourceCondition(product="m365")],
            ),
        ],
    )
