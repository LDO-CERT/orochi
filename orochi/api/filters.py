from enum import Enum

from ninja import Schema


class OPERATING_SYSTEM(str, Enum):
    WINDOWS = "Windows"
    LINUX = "Linux"
    MAC = "Mac"
    OTHER = "Other"


class OperatingSytemFilters(Schema):
    operating_system: OPERATING_SYSTEM = None


class DumpFilters(Schema):
    result: int = None
