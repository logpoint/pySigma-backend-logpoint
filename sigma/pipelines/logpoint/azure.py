from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddConditionTransformation,
)

# 1. Import the base class
from sigma.processing.transformations.base import Transformation
from sigma.rule import SigmaDetectionItem

from sigma.pipelines.logpoint.logpoint_mapping import (
    logpoint_azure_mapping,
    logpoint_azure_activity_taxonomy,
)


# --- 2. Define the Custom Transformation Class ---
# Change inheritance from DetectionItemTransformation -> Transformation
class AzureFieldMappingTransformation(Transformation):
    """
    Custom transformation to map Azure field names dynamically.
    """

    # In V1,we have to implement apply to define how the rule is modified
    def apply(self, rule) -> None:
        # distinct coverage of detection items vs generic rule modification

        # 1. Safety check: ensure rule has detections
        if not rule.detection or not rule.detection.detections:
            return

        # 2. Iterate through all named detections (e.g., 'selection', 'filter')
        for detection in rule.detection.detections.values():
            # 3. Iterate through the actual items in that detection
            for detection_item in detection.detection_items:
                self.transform_detection_item(detection_item)

    def transform_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field = detection_item.field
        # Logic: If field starts with specific string, prepend prefix
        if field and field.lower().startswith("targetresources.modifiedproperties"):
            detection_item.field = "target_modified_property." + field


# --- 3. Update the Pipeline Definition ---
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
            # --- Use the corrected Class ---
            ProcessingItem(
                identifier="logpoint_azure_custom_field_mapping",
                transformation=AzureFieldMappingTransformation(),
                rule_conditions=[LogsourceCondition(product="azure")],
            ),
        ],
    )
