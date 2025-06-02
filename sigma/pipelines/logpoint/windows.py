import dataclasses
import re
from dataclasses import dataclass
from typing import Dict, Union, List, ClassVar, Pattern

from sigma.conditions import ConditionOR
from sigma.pipelines.common import (
    logsource_windows_process_creation,
    logsource_windows_registry_add,
    logsource_windows_file_rename,
    logsource_windows_file_access,
    logsource_windows_file_delete,
    logsource_windows_file_event,
    logsource_windows_file_change,
    logsource_windows_registry_event,
    logsource_windows_registry_delete,
    logsource_windows_registry_set,
    logsource_windows_dns_query,
    logsource_windows_network_connection,
    logsource_windows_create_remote_thread,
    logsource_windows_create_stream_hash,
    logsource_windows_driver_load,
    logsource_windows_raw_access_thread,
    logsource_windows_process_access,
    logsource_windows_pipe_created,
    logsource_windows_image_load,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    RuleContainsDetectionItemCondition,
    IncludeFieldCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformationBase,
    FieldMappingTransformation,
    AddConditionTransformation,
    HashesFieldsDetectionItemTransformation,
)
from sigma.rule import SigmaDetectionItem, SigmaDetection

from sigma.pipelines.logpoint.logpoint_mapping import (
    logpoint_windows_sysmon_variable_mappings,
    logpoint_windows_security_audit_mapping,
    logpoint_windows_service_control_manager_mapping,
    logpoint_windows_common_taxonomy,
    logpoint_windows_sysmon_mapping,
    windows_sysmon_label_mapping,
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


def generate_windows_sysmon_enriched_query(
    identifier_template: str = "windows_sysmon_{category}",
) -> List[ProcessingItem]:
    """Generate processing items for all Windows sysmon mappings for addition of labels.
    :param identifier_template: Template for processing item identifier. Usually, the defaults are
        fine. Should contain service placeholder if changed.
    :type identifier_template: str
    :return: List of ProcessingItem that can be used in the items attribute of a ProcessingPipeline
        object. Usually, an additional field name mapping between the Sigma taxonomy and the target
        system field names is required.
    :rtype: List[ProcessingItem]
    """
    processing_items = []
    for category, additional_fields in windows_sysmon_label_mapping.items():
        for key, val in additional_fields.items():
            if isinstance(val, tuple):
                for item in val:
                    processing_item = ProcessingItem(
                        identifier=identifier_template.format(category=category),
                        transformation=(AddConditionTransformation({key: item})),
                        rule_conditions=[
                            LogsourceCondition(product="windows", category=category)
                        ],
                    )
                    processing_items.append(processing_item)
            else:
                processing_item = ProcessingItem(
                    identifier=identifier_template.format(category=category),
                    transformation=(AddConditionTransformation({key: val})),
                    rule_conditions=[
                        LogsourceCondition(product="windows", category=category)
                    ],
                )
                processing_items.append(processing_item)

    return processing_items


def logpoint_windows_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Logpoint Windows",
        allowed_backends={"logpoint"},
        priority=20,
        items=[
            ProcessingItem(
                field_name_conditions=[IncludeFieldCondition(fields=["Hashes"])],
                identifier="logpoint_windows_hashes_field",
                transformation=HashesFieldsDetectionItemTransformation(
                    valid_hash_algos=["MD5", "SHA1", "SHA256", "SHA512", "IMPHASH"]
                ),
                rule_conditions=[LogsourceCondition(product="windows")],
            )
        ]
        + generate_windows_sysmon_enriched_query()
        + [
            ProcessingItem(
                identifier="logpoint_windows_sysmon_image_mapping",
                transformation=FieldMappingTransformation({field: mapped}),
                rule_conditions=[
                    LogsourceCondition(**{"product": "windows", logsrc_field: logsrc})
                ],
            )
            for field, mappings in logpoint_windows_sysmon_variable_mappings.items()
            for (logsrc_field, logsrc, mapped) in mappings
        ]
        + [
            ProcessingItem(
                identifier="logpoint_windows_sysmon_mapping",
                transformation=FieldMappingTransformation(
                    logpoint_windows_sysmon_mapping
                ),
                rule_condition_linking=any,
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_windows_registry_add(),
                    logsource_windows_registry_set(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_file_change(),
                    logsource_windows_file_event(),
                    logsource_windows_file_delete(),
                    logsource_windows_file_access(),
                    logsource_windows_file_rename(),
                    logsource_windows_image_load(),
                    logsource_windows_pipe_created(),
                    logsource_windows_process_access(),
                    logsource_windows_raw_access_thread(),
                    logsource_windows_driver_load(),
                    logsource_windows_create_stream_hash(),
                    logsource_windows_create_remote_thread(),
                    logsource_windows_network_connection(),
                    logsource_windows_dns_query(),
                    LogsourceCondition(product="windows", category="file_block"),
                    LogsourceCondition(product="windows", category="process_tampering"),
                    LogsourceCondition(
                        product="windows", category="process_termination"
                    ),
                    LogsourceCondition(product="windows", category="raw_access_read"),
                    LogsourceCondition(product="windows", category="clipboard_capture"),
                ],
            ),
            ProcessingItem(
                identifier="logpoint_windows_security_norm_id_enrich",
                transformation=(AddConditionTransformation({"norm_id": "WinServer"})),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="security")
                ],
            ),
        ]
        + [
            ProcessingItem(  # Logpoint's Security Audit Field mappings
                identifier="logpoint_windows_security_event_id_mapping",
                transformation=FieldMappingTransformation(mapping),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="security"),
                    RuleContainsDetectionItemCondition(field="EventID", value=event_id),
                ],
            )
            for event_id, mapping in logpoint_windows_security_audit_mapping.items()
        ]
        + [
            ProcessingItem(  # Logpoint's Security Audit Field mappings
                identifier="logpoint_windows_service_control_manager_mapping",
                transformation=FieldMappingTransformation(mapping),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="system"),
                    RuleContainsDetectionItemCondition(
                        field="Provider_Name", value="Service Control Manager"
                    ),
                    RuleContainsDetectionItemCondition(field="EventID", value=event_id),
                ],
            )
            for event_id, mapping in logpoint_windows_service_control_manager_mapping.items()
        ]
        + [
            ProcessingItem(  # Logpoint's Security Audit Field mappings
                identifier="logpoint_windows_service_control_manager_mapping",
                transformation=FieldMappingTransformation({"Data": "msg"}),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="powershell-classic")
                ],
            ),
            ProcessingItem(  # Generic Field mappings
                identifier="logpoint_windows_generic_field_mapping",
                transformation=SnakeCaseMappingTransformation(
                    logpoint_windows_common_taxonomy
                ),
                field_name_condition_negation=True,
                field_name_condition_linking=any,
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
        ],
    )
