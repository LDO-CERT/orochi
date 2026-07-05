#!/usr/bin/env python3
"""
Export plugin results to CSV, JSON, XLSX, or XML.

Usage:
    from orochi_export import export_results
    data = [{"name": "foo", "value": 1}, {"name": "bar", "value": 2}]
    export_results(data, "csv", "output.csv")
"""

import csv
import json
import os
import xml.etree.ElementTree as ET

def export_results(data, format, filepath):
    """
    Export a list of dictionaries to the specified format.

    Args:
        data (list[dict]): List of rows as dictionaries.
        format (str): One of 'csv', 'json', 'xlsx', 'xml'.
        filepath (str): Output file path.

    Raises:
        ValueError: If format is unsupported.
        ImportError: If openpyxl is not installed for xlsx.
        IOError: If file cannot be written.
    """
    if not data:
        raise ValueError("Data is empty")
    
    format = format.lower()
    if format == 'csv':
        _to_csv(data, filepath)
    elif format == 'json':
        _to_json(data, filepath)
    elif format == 'xlsx':
        _to_xlsx(data, filepath)
    elif format == 'xml':
        _to_xml(data, filepath)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'csv', 'json', 'xlsx', or 'xml'.")

def _to_csv(data, filepath):
    keys = list(data[0].keys())
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

def _to_json(data, filepath):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def _to_xlsx(data, filepath):
    try:
        import openpyxl
    except ImportError:
        raise ImportError("openpyxl is required for XLSX export. Install with: pip install openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    keys = list(data[0].keys())
    ws.append(keys)
    for row in data:
        ws.append([row.get(key, '') for key in keys])
    wb.save(filepath)

def _to_xml(data, filepath):
    root = ET.Element("results")
    for row in data:
        elem = ET.SubElement(root, "row")
        for key, value in row.items():
            child = ET.SubElement(elem, _sanitize_xml_tag(key))
            child.text = str(value) if value is not None else ''
    tree = ET.ElementTree(root)
    tree.write(filepath, encoding='utf-8', xml_declaration=True)

def _sanitize_xml_tag(tag):
    """Make a valid XML tag from a string."""
    tag = str(tag)
    tag = tag.replace(' ', '_')
    tag = tag.replace('-', '_')
    # Remove any other invalid characters (simplistic)
    tag = ''.join(c for c in tag if c.isalnum() or c in ('_', '.'))
    if tag[0].isdigit():
        tag = '_' + tag
    return tag or 'field'
