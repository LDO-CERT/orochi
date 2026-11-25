"""Server-side full-result export helpers (CSV, JSON, XLSX, XML) for Issue #1559."""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

_ILLEGAL_XML_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]")
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_SAFE_XML_TAG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _clean_xml_text(value: Any) -> str:
    """Convert any cell value to a string free of illegal XML 1.0 control characters."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    return _ILLEGAL_XML_RE.sub("", text)


def _safe_xml_tag(name: str, fallback_idx: int) -> str:
    """Return a valid XML element name derived from a column header."""
    cleaned = _SAFE_XML_TAG_RE.sub("_", str(name or "").strip()).strip(".-")
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = f"col_{cleaned}" if cleaned else f"column_{fallback_idx}"
    if cleaned.lower().startswith("xml"):
        cleaned = f"col_{cleaned}"
    return cleaned


def build_export_filename(dump_names: list[str], plugin_name: str, fmt: str) -> str:
    """Build a safe download filename identifying the dump(s) and plugin."""
    if len(dump_names) == 1:
        dump_part = _SAFE_FILENAME_RE.sub("_", dump_names[0]).strip("._-") or "dump"
    elif dump_names:
        first = _SAFE_FILENAME_RE.sub("_", dump_names[0]).strip("._-") or "dump"
        dump_part = f"{first}_and_{len(dump_names) - 1}_more"
    else:
        dump_part = "orochi"
    plugin_part = _SAFE_FILENAME_RE.sub("_", plugin_name).strip("._-") or "plugin"
    ext = fmt.lower().lstrip(".")
    return f"{dump_part}_{plugin_part}.{ext}"


def _format_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_NUMBER_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")


def _neutralize_formula(text: str) -> str:
    """Prefix ``'`` to strings a spreadsheet would run as a formula (memory data is attacker controlled).

    Plain numbers (``-1``) and the ``-`` placeholder are kept as they are.
    """
    if text and text.startswith(_FORMULA_PREFIXES) and text != "-" and not _NUMBER_RE.match(text):
        return "'" + text
    return text


def export_rows_csv(columns: list[str], rows: list[dict[str, Any]]) -> bytes:
    """Serialize all rows as UTF-8 CSV, with formula-like cells neutralized (CSV injection)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([_neutralize_formula(str(c)) for c in columns])
    for row in rows:
        writer.writerow([_neutralize_formula(_format_cell(row.get(col))) for col in columns])
    return buf.getvalue().encode("utf-8")


def export_rows_json(columns: list[str], rows: list[dict[str, Any]]) -> bytes:
    """Serialize all rows as a UTF-8 JSON array of objects."""
    ordered = [{col: row.get(col) for col in columns} for row in rows]
    return json.dumps(ordered, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def export_rows_xml(columns: list[str], rows: list[dict[str, Any]]) -> bytes:
    """Serialize all rows as well-formed UTF-8 XML."""
    root = ET.Element("data")
    tag_map = [(col, _safe_xml_tag(col, idx)) for idx, col in enumerate(columns)]
    for row in rows:
        row_el = ET.SubElement(root, "row")
        for col, tag in tag_map:
            cell_el = ET.SubElement(row_el, tag)
            cell_el.text = _clean_xml_text(row.get(col))
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def _col_letter(idx: int) -> str:
    """Convert 0-based column index to Excel column letters (A, B, ..., Z, AA, ...)."""
    result = ""
    n = idx + 1
    while n > 0:
        n, rem = divmod(n - 1, 26)
        result = chr(65 + rem) + result
    return result


def export_rows_xlsx(columns: list[str], rows: list[dict[str, Any]]) -> bytes:
    """Serialize all rows as a standards-compliant OOXML .xlsx workbook without external dependencies."""
    sheet_lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        "<sheetData>",
    ]

    def _emit_row(row_num: int, values: list[Any]) -> str:
        cells = []
        for c_idx, val in enumerate(values):
            ref = f"{_col_letter(c_idx)}{row_num}"
            if isinstance(val, bool):
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{str(val)}</t></is></c>')
            elif isinstance(val, (int, float)):
                cells.append(f'<c r="{ref}"><v>{val}</v></c>')
            else:
                text = xml_escape(_clean_xml_text(val))
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>')
        return f'<row r="{row_num}">{"".join(cells)}</row>'

    sheet_lines.append(_emit_row(1, columns))
    for r_idx, row in enumerate(rows, start=2):
        sheet_lines.append(_emit_row(r_idx, [row.get(col) for col in columns]))
    sheet_lines.append("</sheetData></worksheet>")
    sheet_xml = "".join(sheet_lines).encode("utf-8")

    content_types = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        b'<Default Extension="xml" ContentType="application/xml"/>'
        b'<Override PartName="/xl/workbook.xml" '
        b'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        b'<Override PartName="/xl/worksheets/sheet1.xml" '
        b'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        b"</Types>"
    )

    root_rels = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        b'Target="xl/workbook.xml"/>'
        b"</Relationships>"
    )

    workbook_xml = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        b'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        b'<sheets><sheet name="Results" sheetId="1" r:id="rId1"/></sheets>'
        b"</workbook>"
    )

    workbook_rels = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        b'Target="worksheets/sheet1.xml"/>'
        b"</Relationships>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()
