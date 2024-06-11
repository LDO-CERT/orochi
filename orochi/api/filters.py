from enum import Enum
from typing import List

from ninja import Schema
from pydantic import root_validator


class OPERATING_SYSTEM(str, Enum):
    WINDOWS = "Windows"
    LINUX = "Linux"
    MAC = "Mac"
    OTHER = "Other"


class OperatingSytemFilters(Schema):
    operating_system: OPERATING_SYSTEM = None


class DumpFilters(Schema):
    result: int = None


###################################################
# Rules
###################################################
class Search(Schema):
    value: str = None
    regex: bool = False


class Column(Schema):
    data: int
    name: str = None
    searchable: bool = True
    orderable: bool = True
    search: Search = None


class Order(Schema):
    column: int = 0
    dir: str = "asc"


class RulesFilter(Schema):
    start: int = 0
    length: int = 10
    columns: List[Column] = []
    search: Search = None
    order: List[Order] = []

    @root_validator(pre=True)
    def extract_data(cls, v):
        return v
