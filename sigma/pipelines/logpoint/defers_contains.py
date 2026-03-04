from sigma.pipelines.common import generate_windows_logsource_items
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import SetCustomAttributeTransformation


def logpoint_defer_contains() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Logpoint Defer Contain Expression",
        allowed_backends={"logpoint"},
        priority=20,
        items=[
            ProcessingItem(
                identifier="marker_defer_contains",
                transformation=SetCustomAttributeTransformation(
                    attribute="_logpoint_marker_defer_contains",
                    value=True,
                ),
            ),
        ],
    )
