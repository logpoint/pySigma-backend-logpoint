from typing import Dict, Union, List, ClassVar, Pattern
import re
from dataclasses import dataclass


from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformationBase,
    FieldMappingTransformation,
    AddConditionTransformation,
)
from sigma.rule import SigmaDetectionItem, SigmaDetection
from sigma.conditions import ConditionOR
import dataclasses

from sigma.pipelines.logpoint.logpoint_mapping import (
    logpoint_linux_auditd_mapping,
    logpoint_linux_common_taxonomy,
)


@dataclass
class SnakeCaseMappingTransformation(FieldMappingTransformationBase):
    """Map a field name to one or multiple different."""

    mapping: Dict[str, Union[str, List[str]]]
    _re_to_snake_case: ClassVar[Pattern] = re.compile(
        "([a-z0-9]+|[A-Z][a-z0-9]+|[A-Z0-9]+)"
    )

    def to_snake_case(self, key):
        """_to_snake_case converts the fields to snake_case

        Args:
            key (str): field name in any other case

        Returns:
            snake_case (str): filed name converted to the snake_case
        """
        words = self._re_to_snake_case.findall(key)
        if len(words) > 1:
            snake_case = "_".join(words).lower()
        else:
            snake_case = words[0].lower()
        return snake_case

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        if field in self.mapping:
            mapping = self.mapping[field]
            return mapping

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        super().apply_detection_item(detection_item)
        field = detection_item.field
        mapping = self.get_mapping(field) or self.to_snake_case(field)
        if mapping is not None and self.processing_item.match_field_name(
            self._pipeline, field
        ):
            self._pipeline.field_mappings.add_mapping(field, mapping)
            if isinstance(
                mapping, str
            ):  # 1:1 mapping, map field name of detection item directly
                detection_item.field = mapping
                self.processing_item_applied(detection_item)
            else:
                return SigmaDetection(
                    [
                        dataclasses.replace(
                            detection_item, field=field, auto_modifiers=False
                        )
                        for field in mapping
                    ],
                    item_linking=ConditionOR,
                )

    def apply_field_name(self, field: str) -> Union[str, List[str]]:
        mapping = self.get_mapping(field) or self.to_snake_case(field)
        if isinstance(mapping, str):
            return [mapping]
        else:
            return mapping


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
