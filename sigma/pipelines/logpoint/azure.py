import re
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddConditionTransformation,
    FieldFunctionTransformation,
)

from sigma.pipelines.logpoint.logpoint_mapping import (
    logpoint_azure_mapping,
    logpoint_azure_activity_taxonomy,
)


def azure_field_mapping(field: str) -> str:
    # 1. Handle specific prefix logic
    if field and field.lower().startswith("targetresources.modifiedproperties"):
        return "target_modified_property." + field

    # 2. Fallback: Dynamic snake_case conversion
    if not field:
        return field

    words = re.findall(r"([a-z0-9]+|[A-Z][a-z0-9]+|[A-Z0-9]+)", field)
    if len(words) > 1:
        return "_".join(words).lower()
    return words[0].lower() if words else field.lower()


def logpoint_azure_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Logpoint Azure",
        allowed_backends={"logpoint"},
        priority=20,
        items=[
            ProcessingItem(
                identifier="logpoint_azure_taxonomy",
                transformation=FieldMappingTransformation(logpoint_azure_mapping),
                rule_conditions=[
                    LogsourceCondition(**{"product": "azure", "service": "signinlogs"}),
                    LogsourceCondition(**{"product": "azure", "service": "auditlogs"}),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="logpoint_azure_activity_taxonomy",
                transformation=FieldMappingTransformation(
                    logpoint_azure_activity_taxonomy
                ),
                rule_conditions=[
                    LogsourceCondition(
                        **{"product": "azure", "service": "activitylogs"}
                    )
                ],
            ),
            ProcessingItem(
                identifier="logpoint_azure_signinlogs_enrich",
                transformation=(
                    AddConditionTransformation(
                        {"norm_id": "AzureLogAnalytics", "event_type": "SigninLogs"}
                    )
                ),
                rule_conditions=[
                    LogsourceCondition(product="azure", service="signinlogs")
                ],
            ),
            ProcessingItem(
                identifier="logpoint_azure_auditlogs_enrich",
                transformation=(
                    AddConditionTransformation(
                        {"norm_id": "AzureLogAnalytics", "event_type": "AuditLogs"}
                    )
                ),
                rule_conditions=[
                    LogsourceCondition(product="azure", service="auditlogs")
                ],
            ),
            ProcessingItem(
                identifier="logpoint_azure_activity_enrich",
                transformation=(
                    AddConditionTransformation({"norm_id": "MicrosoftAzure"})
                ),
                rule_conditions=[
                    LogsourceCondition(product="azure", service="activitylogs")
                ],
            ),
            ProcessingItem(
                identifier="logpoint_azure_custom_field_mapping",
                transformation=FieldFunctionTransformation(
                    mapping={}, transform_func=azure_field_mapping
                ),
                rule_conditions=[LogsourceCondition(product="azure")],
            ),
        ],
    )
