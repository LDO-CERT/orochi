"""Sidebar split into Workbench (dumps + plugins) and Cases tabs, with a Cases entry in the top bar."""

import pytest
from django.urls import reverse

pytestmark = pytest.mark.django_db


def test_index_has_workbench_and_cases_tabs_and_top_bar_entry(client, admin):
    client.force_login(admin)
    html = client.get(reverse("website:index")).content.decode()
    for marker in (
        'data-sidebar-tab="workbench"',
        'data-sidebar-tab="cases"',
        'data-sidebar-panel="workbench"',
        'data-sidebar-panel="cases"',
        'id="list_plugin"',
        'id="cases_list"',
    ):
        assert marker in html, marker
    assert "?tab=cases" in html and "showSidebarTab('cases', true)" in html
    # dumps and plugins stay in the same panel (plugins depend on the selected dumps)
    wb = html[html.index('data-sidebar-panel="workbench"') :]
    assert "Dumps" in wb[: wb.index('id="list_plugin"')]


def test_active_page_colours_its_top_bar_icon(client, admin):
    client.force_login(admin)
    html = client.get(reverse("website:list_playbooks")).content.decode()
    assert "fa-wand-magic-sparkles text-sm transition-colors text-indigo-500" in html
    assert "group-hover:text-emerald-500" in html  # other entries take their colour on hover
