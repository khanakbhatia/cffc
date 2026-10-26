from . import aws_cloudtrail, azure_activity, gcp_audit
from .aws_cloudtrail import NormalizationError

NORMALIZERS = {
    "aws": aws_cloudtrail.normalize_record,        # implemented + exercised (synthetic; real pending)
    "azure": azure_activity.normalize_record,      # design-level mapping only
    "gcp": gcp_audit.normalize_record,             # design-level mapping only
}

__all__ = ["NORMALIZERS", "NormalizationError"]
