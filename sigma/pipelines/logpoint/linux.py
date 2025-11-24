from typing import Dict, Union, List, ClassVar, Pattern
import re
import dataclasses
from dataclasses import dataclass

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
)

# Import base Transformation explicitly
from sigma.processing.transformations.base import Transformation
from sigma.rule import SigmaDetectionItem

from sigma.pipelines.logpoint.logpoint_mapping import (
    logpoint_linux_auditd_mapping,
    logpoint_linux_common_taxonomy,
)


@dataclass
class SnakeCaseMappingTransformation(Transformation):
    """
    Map a field name to one or multiple different fields using a dictionary,
    or fallback to converting the field name to snake_case if not found.

    Compatible with pySigma v1.0.0.
    """

    mapping: Dict[str, Union[str, List[str]]]
    _re_to_snake_case: ClassVar[Pattern] = re.compile(
        "([a-z0-9]+|[A-Z][a-z0-9]+|[A-Z0-9]+)"
    )

    def to_snake_case(self, key):
        """Convert field name to snake_case."""
        words = self._re_to_snake_case.findall(key)
        if len(words) > 1:
            snake_case = "_".join(words).lower()
        else:
            snake_case = words[0].lower()
        return snake_case

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        # 1. Check explicit mapping
        if field in self.mapping:
            return self.mapping[field]
        # 2. Fallback to snake_case conversion
        return self.to_snake_case(field)

    def apply(self, rule) -> None:
        """
        Entry point for pySigma 1.0.0.
        Iterates over all detections and applies the field mapping.
        """
        if not rule.detection or not rule.detection.detections:
            return

        # Iterate over named detections (e.g., 'selection', 'filter')
        for detection in rule.detection.detections.values():
            new_detection_items = []

            # Process every item in the detection
            for detection_item in detection.detection_items:
                result = self.transform_detection_item(detection_item)

                # If the result is a list (1-to-Many mapping), extend the items
                if isinstance(result, list):
                    new_detection_items.extend(result)
                else:
                    new_detection_items.append(result)

            # Replace the detection items with the transformed list
            detection.detection_items = new_detection_items

    def transform_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Union[SigmaDetectionItem, List[SigmaDetectionItem]]:
        field = detection_item.field
        # If no field name (e.g., keyword search), skip
        if not field:
            return detection_item

        target = self.get_mapping(field)

        # Case 1: 1:1 Mapping (String)
        if isinstance(target, str):
            detection_item.field = target
            return detection_item

        # Case 2: 1:N Mapping (List of strings)
        # Expands one item into multiple items (one for each new field name)
        elif isinstance(target, list):
            expanded_items = []
            for new_field in target:
                # Create a copy of the item for each mapped field
                new_item = dataclasses.replace(detection_item, field=new_field)
                expanded_items.append(new_item)
            return expanded_items

        return detection_item


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
                transformation=SnakeCaseMappingTransformation(
                    logpoint_linux_common_taxonomy
                ),
                rule_conditions=[
                    LogsourceCondition(product="linux"),
                ],
            ),
        ],
    )
