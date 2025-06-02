from .windows import logpoint_windows_pipeline
from .m365 import logpoint_m365_pipeline
from .azure import logpoint_azure_pipeline

pipelines = {
    "logpoint_windows": logpoint_windows_pipeline,
    "logpoint_o365": logpoint_m365_pipeline,
    "logpoint_azure": logpoint_azure_pipeline,
}
