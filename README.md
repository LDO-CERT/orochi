# orochi-export

A small module to export list-of-dicts data to CSV, JSON, XLSX, or XML.

## Usage

```python
from orochi_export import export_results

data = [
    {"name": "Alice", "score": 95},
    {"name": "Bob", "score": 87}
]

export_results(data, "csv", "output.csv")
export_results(data, "json", "output.json")
export_results(data, "xlsx", "output.xlsx")  # requires openpyxl
export_results(data, "xml", "output.xml")
```

## Requirements

- Python 3.6+
- For XLSX: `openpyxl` (`pip install openpyxl`)

## Note

This is a self-contained warm-up contribution for [Orochi](https://github.com/LDO-CERT/orochi) F5 task.
