"""Native GTK4 + libadwaita desktop GUI for the File Integrity Monitor."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import gi

gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango

from . import __version__
from .baseline import load_baseline
from .errors import BaselineExistsError, FimError
from .service import baseline_path_for, check_integrity, create_baseline, resolve_directory


@dataclass
class HistoryEntry:
    time: str
    directory: str
    baseline: str
    result: str
    warnings: int
    modified: int
    added: int
    deleted: int
    unchanged: int
    scanned: int


class FimApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id="org.fileintegritymonitor.Fim", flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.window = None

    def do_activate(self) -> None:
        if self.window is not None:
            self.window.present()
            return
        self.window = FimWindow(self)
        self.window.present()


class FimWindow(Adw.ApplicationWindow):
    def __init__(self, app: FimApp) -> None:
        super().__init__(application=app)
        self.set_title("File Integrity Monitor")
        self.set_default_size(1180, 780)
        self.set_size_request(920, 640)

        self._history: list[HistoryEntry] = []
        self._report: dict | None = None
        self._filter_type = "all"
        self._history_file = Path(GLib.get_user_data_dir()) / "file-integrity-monitor" / "history.json"
        self._history_file.parent.mkdir(parents=True, exist_ok=True)

        self._load_history()

        self._build_ui()
        self._apply_css()
        self._refresh_baseline()

    # -- UI construction -------------------------------------------------

    def _build_ui(self) -> None:
        # Header
        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(True)
        header.set_show_end_title_buttons(True)

        app_icon = Gtk.Image.new_from_file("/home/kali/Documents/file_integrity_monitor/assets/logo/fim-logo.png")
        app_icon.set_pixel_size(20)
        icon_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        icon_box.set_margin_start(6)
        icon_box.append(app_icon)
        header.pack_start(icon_box)

        self.title_label = Gtk.Label(label="File Integrity Monitor")
        self.title_label.set_css_classes(["title"])
        header.set_title_widget(self.title_label)

        about_button = Gtk.Button(icon_name="help-about-symbolic")
        about_button.set_tooltip_text("About File Integrity Monitor")
        about_button.connect("clicked", self._show_about)
        header.pack_end(about_button)

        refresh_button = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_button.set_tooltip_text("Refresh baseline info (F5)")
        refresh_button.connect("clicked", lambda *_: self._refresh_baseline())
        header.pack_end(refresh_button)

        watermark_label = Gtk.Label(label="Created by 0xtor.exe")
        watermark_label.set_css_classes(["dim-label", "caption"])
        watermark_label.set_margin_end(10)
        header.pack_end(watermark_label)

        # Main layout
        split = Adw.NavigationSplitView()
        split.set_min_sidebar_width(360)
        split.set_max_sidebar_width(420)

        sidebar = self._build_sidebar()
        content = self._build_content()

        split.set_sidebar(Adw.NavigationPage.new(sidebar, "Controls"))
        split.set_content(Adw.NavigationPage.new(content, "Report"))

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(split)

        self.set_content(toolbar)

    def _build_sidebar(self) -> Gtk.Widget:
        page_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        page_box.set_css_classes(["sidebar"])

        clamp = Adw.Clamp()
        clamp.set_maximum_size(440)
        clamp.set_margin_start(12)
        clamp.set_margin_end(12)
        clamp.set_margin_top(12)
        clamp.set_margin_bottom(12)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(self._build_target_group())
        box.append(self._build_baseline_group())

        clamp.set_child(box)
        page_box.append(clamp)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(page_box)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        return scrolled

    def _build_target_group(self) -> Gtk.Widget:
        group = Adw.PreferencesGroup()
        group.set_title("Scan Target")
        group.set_description("Choose a directory to monitor with SHA-256 hashing")

        # Directory row
        self.directory_entry = Adw.EntryRow(title="Directory")
        self.directory_entry.set_text("")
        self.directory_entry.connect("changed", lambda *_: self._on_target_changed())
        group.add(self.directory_entry)

        browse_row = Adw.ActionRow(title="Browse for folder")
        browse_row.set_subtitle("Pick a directory with the file picker")
        browse_btn = Gtk.Button(label="Browse")
        browse_btn.set_valign(Gtk.Align.CENTER)
        browse_btn.connect("clicked", self._browse_directory)
        browse_row.add_suffix(browse_btn)
        group.add(browse_row)

        # Baseline row
        self.baseline_entry = Adw.EntryRow(title="Baseline file (optional)")
        try:
            self.baseline_entry.set_placeholder_text("Default: <directory>/.fim_baseline.json")
        except Exception:
            pass
        self.baseline_entry.connect("changed", lambda *_: self._on_target_changed())
        group.add(self.baseline_entry)

        # Excludes
        excludes_expander = Adw.ExpanderRow(title="Exclude patterns")
        excludes_expander.set_subtitle("Skip files matching glob patterns")
        self.excludes_buffer = Gtk.TextBuffer()
        excludes_view = Gtk.TextView(buffer=self.excludes_buffer)
        excludes_view.set_monospace(True)
        excludes_view.set_wrap_mode(Gtk.WrapMode.NONE)
        excludes_view.set_left_margin(8)
        excludes_view.set_right_margin(8)
        excludes_view.set_top_margin(8)
        excludes_view.set_bottom_margin(8)

        excludes_frame = Gtk.Frame()
        excludes_frame.set_child(excludes_view)
        excludes_frame.set_margin_start(12)
        excludes_frame.set_margin_end(12)
        excludes_frame.set_margin_bottom(12)

        excludes_scroll = Gtk.ScrolledWindow()
        excludes_scroll.set_min_content_height(90)
        excludes_scroll.set_child(excludes_frame)

        excludes_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        excludes_box.append(excludes_scroll)
        hint = Gtk.Label(label="One pattern per line (e.g. *.log, cache/*)")
        hint.set_xalign(0)
        hint.set_margin_start(12)
        hint.set_margin_end(12)
        hint.set_margin_bottom(10)
        hint.set_css_classes(["dim-label", "caption"])
        excludes_box.append(hint)
        excludes_expander.add_row(Adw.ActionRow())
        # easier: add custom child
        # Adw.ExpanderRow doesn't take arbitrary child easily, add action rows
        excludes_row = Adw.ActionRow()
        excludes_row.set_child(excludes_box)
        excludes_row.set_activatable(False)
        excludes_expander.add_row(excludes_row)
        group.add(excludes_expander)

        # Actions
        actions_row = Adw.ActionRow()
        actions_row.set_activatable(False)

        actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions_box.set_homogeneous(True)
        actions_box.set_margin_top(6)
        actions_box.set_margin_bottom(6)
        actions_box.set_margin_start(0)
        actions_box.set_margin_end(0)

        self.baseline_btn = Gtk.Button(label="Create Baseline")
        self.baseline_btn.set_css_classes(["suggested-action"])
        self.baseline_btn.connect("clicked", self._create_baseline)
        actions_box.append(self.baseline_btn)

        self.check_btn = Gtk.Button(label="Run Check")
        self.check_btn.connect("clicked", self._run_check)
        actions_box.append(self.check_btn)

        actions_row.set_child(actions_box)
        group.add(actions_row)

        self.hint_label = Gtk.Label(label="Select a directory to begin.")
        self.hint_label.set_xalign(0)
        self.hint_label.set_wrap(True)
        self.hint_label.set_css_classes(["dim-label"])
        self.hint_label.set_margin_top(4)
        group.add(Adw.ActionRow(child=self.hint_label, activatable=False))

        return group

    def _build_baseline_group(self) -> Gtk.Widget:
        group = Adw.PreferencesGroup()
        group.set_title("Baseline Status")

        self.baseline_status_row = Adw.ActionRow(title="Status")
        self.baseline_status_row.set_subtitle("No directory selected")
        self.baseline_icon = Gtk.Image.new_from_icon_name("dialog-question-symbolic")
        self.baseline_status_row.add_prefix(self.baseline_icon)
        group.add(self.baseline_status_row)

        self.baseline_created_row = Adw.ActionRow(title="Created")
        self.baseline_created_row.set_subtitle("—")
        group.add(self.baseline_created_row)
        self.baseline_files_row = Adw.ActionRow(title="Files")
        self.baseline_files_row.set_subtitle("—")
        group.add(self.baseline_files_row)
        self.baseline_path_row = Adw.ActionRow(title="Baseline file")
        self.baseline_path_row.set_subtitle("—")
        self.baseline_path_row.set_subtitle_selectable(True)
        self.baseline_root_row = Adw.ActionRow(title="Root")
        self.baseline_root_row.set_subtitle("—")
        self.baseline_root_row.set_subtitle_selectable(True)
        group.add(self.baseline_path_row)
        group.add(self.baseline_root_row)

        self.baseline_info_label = Gtk.Label(label="A baseline records trusted SHA-256 hashes for future comparison.")
        self.baseline_info_label.set_xalign(0)
        self.baseline_info_label.set_wrap(True)
        self.baseline_info_label.set_css_classes(["dim-label"])
        info_row = Adw.ActionRow()
        info_row.set_child(self.baseline_info_label)
        info_row.set_activatable(False)
        group.add(info_row)

        return group

    def _build_content(self) -> Gtk.Widget:
        page_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # Summary bar
        self.summary_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.summary_box.set_margin_start(16)
        self.summary_box.set_margin_end(16)
        self.summary_box.set_margin_top(16)
        self.summary_box.set_homogeneous(True)
        self.summary_box.set_visible(False)

        self._add_summary_card("modified", "Modified", "#f59e0b")
        self._add_summary_card("added", "Added", "#22c55e")
        self._add_summary_card("deleted", "Deleted", "#ef4444")
        self._add_summary_card("unchanged", "Unchanged", "#94a3b8")
        page_box.append(self.summary_box)

        # Warnings
        self.warnings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.warnings_box.set_margin_start(16)
        self.warnings_box.set_margin_end(16)
        self.warnings_box.set_margin_top(10)
        self.warnings_box.set_visible(False)
        page_box.append(self.warnings_box)

        # Filter
        self.filter_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.filter_box.set_margin_start(16)
        self.filter_box.set_margin_end(16)
        self.filter_box.set_margin_top(14)
        self.filter_box.set_visible(False)

        self.filter_group = Gtk.ToggleButton()
        self.filter_all = Gtk.ToggleButton(label="All 0")
        self.filter_all.set_active(True)
        self.filter_all.connect("toggled", lambda b: self._on_filter_toggled(b, "all"))
        self.filter_box.append(self.filter_all)

        self.filter_mod = Gtk.ToggleButton(label="Modified 0")
        self.filter_mod.set_group(self.filter_all)
        self.filter_mod.connect("toggled", lambda b: self._on_filter_toggled(b, "modified"))
        self.filter_box.append(self.filter_mod)

        self.filter_add = Gtk.ToggleButton(label="Added 0")
        self.filter_add.set_group(self.filter_all)
        self.filter_add.connect("toggled", lambda b: self._on_filter_toggled(b, "added"))
        self.filter_box.append(self.filter_add)

        self.filter_del = Gtk.ToggleButton(label="Deleted 0")
        self.filter_del.set_group(self.filter_all)
        self.filter_del.connect("toggled", lambda b: self._on_filter_toggled(b, "deleted"))
        self.filter_box.append(self.filter_del)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        self.filter_box.append(spacer)

        self.scan_meta_label = Gtk.Label()
        self.scan_meta_label.set_css_classes(["dim-label"])
        self.filter_box.append(self.scan_meta_label)
        page_box.append(self.filter_box)

        # Stack
        self.stack = Gtk.Stack()
        self.stack.set_vexpand(True)
        self.stack.set_margin_start(16)
        self.stack.set_margin_end(16)
        self.stack.set_margin_top(10)
        self.stack.set_margin_bottom(12)

        # Empty state
        self.empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.empty_box.set_halign(Gtk.Align.CENTER)
        self.empty_box.set_valign(Gtk.Align.CENTER)
        self.empty_box.set_vexpand(True)
        empty_icon = Gtk.Image.new_from_icon_name("document-open-symbolic")
        empty_icon.set_pixel_size(56)
        empty_icon.set_opacity(0.5)
        self.empty_box.append(empty_icon)
        empty_title = Gtk.Label(label="No report yet")
        empty_title.set_css_classes(["title-2"])
        self.empty_box.append(empty_title)
        empty_sub = Gtk.Label(label="Create a baseline or run an integrity check to see results")
        empty_sub.set_css_classes(["dim-label"])
        empty_sub.set_wrap(True)
        self.empty_box.append(empty_sub)
        self.stack.add_named(self.empty_box, "empty")

        # List
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.set_css_classes(["boxed-list"])
        self.list_box.set_valign(Gtk.Align.START)

        list_scroll = Gtk.ScrolledWindow()
        list_scroll.set_child(self.list_box)
        list_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.stack.add_named(list_scroll, "list")

        # Clean state
        self.clean_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.clean_box.set_halign(Gtk.Align.CENTER)
        self.clean_box.set_valign(Gtk.Align.CENTER)
        self.clean_box.set_vexpand(True)
        clean_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
        clean_icon.set_pixel_size(56)
        clean_icon.set_opacity(0.9)
        clean_icon.set_css_classes(["success"])
        self.clean_box.append(clean_icon)
        clean_title = Gtk.Label(label="No changes detected")
        clean_title.set_css_classes(["title-2"])
        self.clean_box.append(clean_title)
        clean_sub = Gtk.Label(label="All files match the baseline")
        clean_sub.set_css_classes(["dim-label"])
        self.clean_box.append(clean_sub)
        self.stack.add_named(self.clean_box, "clean")

        page_box.append(self.stack)

        # History
        history_group = Adw.PreferencesGroup()
        history_group.set_title("Recent Checks")
        history_group.set_description("Double-click a row to reload the target directory")
        history_group.set_margin_start(16)
        history_group.set_margin_end(16)
        history_group.set_margin_bottom(14)

        self.history_list = Gtk.ListBox()
        self.history_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.history_list.set_css_classes(["boxed-list"])
        self.history_list.connect("row-activated", self._load_history_entry)
        self.history_list.connect("row-selected", lambda *_: None)

        self.history_empty = Gtk.Label(label="No checks run yet in this app")
        self.history_empty.set_css_classes(["dim-label"])
        self.history_empty.set_margin_top(6)
        self.history_empty.set_margin_bottom(6)
        self.history_empty_row = Adw.ActionRow()
        self.history_empty_row.set_child(self.history_empty)
        self.history_empty_row.set_activatable(False)
        self.history_list.append(self.history_empty_row)

        history_row_wrap = Adw.ActionRow()
        history_row_wrap.set_child(self.history_list)
        history_row_wrap.set_activatable(False)
        history_group.add(history_row_wrap)

        clear_row = Adw.ActionRow(title="Clear history")
        clear_row.set_subtitle("Remove all recent checks from this list")
        clear_btn = Gtk.Button(label="Clear")
        clear_btn.set_valign(Gtk.Align.CENTER)
        clear_btn.connect("clicked", self._clear_history)
        clear_row.add_suffix(clear_btn)
        history_group.add(clear_row)

        page_box.append(history_group)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(page_box)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        return scrolled

    def _add_summary_card(self, key: str, label: str, color: str) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        card.set_css_classes(["card", "summary-card"])
        card.get_style_context().add_class(f"summary-{key}")

        value = Gtk.Label(label="0")
        value.set_css_classes(["summary-value"])
        value.set_xalign(0)
        setattr(self, f"summary_{key}_value", value)
        card.append(value)

        lbl = Gtk.Label(label=label)
        lbl.set_css_classes(["summary-label"])
        lbl.set_xalign(0)
        card.append(lbl)
        self.summary_box.append(card)

    def _apply_css(self) -> None:
        css = """
        .sidebar { background: alpha(@window_bg_color, 0.4); }
        .summary-card { padding: 14px 16px; }
        .summary-value { font-size: 28px; font-weight: 700; }
        .summary-label { opacity: 0.7; }
        .summary-modified .summary-value { color: #f59e0b; }
        .summary-added .summary-value { color: #22c55e; }
        .summary-deleted .summary-value { color: #ef4444; }
        .summary-unchanged .summary-value { color: #94a3b8; }
        .success { color: #22c55e; }
        .warning { color: #f59e0b; }
        .danger { color: #ef4444; }
        .dim-label { opacity: 0.6; }
        .caption { font-size: 11px; }
        .code { font-family: monospace; font-size: 11px; }
        .hash { font-family: monospace; font-size: 10px; opacity: 0.8; }
        .change-modified { border-left: 3px solid #f59e0b; }
        .change-added { border-left: 3px solid #22c55e; }
        .change-deleted { border-left: 3px solid #ef4444; }
        """
        provider = Gtk.CssProvider()
        provider.load_from_string(css)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

    # -- Helpers ---------------------------------------------------------

    def _get_directory(self) -> str:
        return self.directory_entry.get_text().strip()

    def _get_baseline(self) -> str | None:
        text = self.baseline_entry.get_text().strip()
        return text or None

    def _get_excludes(self) -> list[str]:
        text = self.excludes_buffer.get_text(
            self.excludes_buffer.get_start_iter(),
            self.excludes_buffer.get_end_iter(),
            False,
        )
        return [line.strip() for line in text.splitlines() if line.strip()]

    def _on_target_changed(self) -> None:
        self._refresh_baseline()
        self._update_hint()

    def _update_hint(self) -> None:
        if not self._get_directory():
            self.hint_label.set_label("Select a directory to begin.")
            return
        if self._baseline_state == "error":
            self.hint_label.set_label("Fix the baseline issue, then run a check.")
            return
        if self._baseline_state == "ready":
            self.hint_label.set_label("Baseline ready. Run a check to detect changes.")
            return
        self.hint_label.set_label("No baseline yet. Create one to start monitoring.")

    def _browse_directory(self, _btn) -> None:
        dialog = Gtk.FileDialog()
        dialog.set_title("Select directory to monitor")
        dialog.select_folder(self, None, self._on_folder_selected)

    def _on_folder_selected(self, dialog, result) -> None:
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                path = folder.get_path()
                self.directory_entry.set_text(path)
                self._refresh_baseline()
                self.toast("Scan target updated")
        except GLib.Error:
            pass

    def _show_toast(self, message: str) -> None:
        self.toast(message)

    def toast(self, message: str) -> None:
        toast = Adw.Toast.new(message)
        toast.set_timeout(3)
        overlay = getattr(self, "_toast_overlay", None)
        if overlay is not None:
            overlay.add_toast(toast)
            return
        root = self.get_content()
        def find_overlay(widget):
            if isinstance(widget, Adw.ToastOverlay):
                widget.add_toast(toast)
                return True
            child = widget.get_first_child()
            if child and find_overlay(child):
                return True
            child2 = widget.get_last_child()
            if child2 and child2 is not child and find_overlay(child2):
                return True
            return False
        find_overlay(root)

    def _show_about(self, _btn) -> None:
        about = Adw.AboutWindow(transient_for=self)
        about.set_application_name("File Integrity Monitor")
        about.set_application_icon("/home/kali/Documents/file_integrity_monitor/assets/logo/fim-logo.png")
        about.set_developer_name("0xtor.exe")
        about.set_version(__version__)
        about.set_comments("Native desktop application for detecting file changes using SHA-256 hashing.\nCreated by 0xtor.exe")
        about.set_license_type(Gtk.License.MIT_X11)
        about.set_copyright("\u00a9 2026 0xtor.exe")
        about.present()

    def _set_busy(self, busy: bool) -> None:
        self.baseline_btn.set_sensitive(not busy)
        self.check_btn.set_sensitive(not busy)
        self.directory_entry.set_sensitive(not busy)
        self.baseline_entry.set_sensitive(not busy)
        try:
            self.set_sensitive(not busy)
        except Exception:
            pass

    def _baseline_path(self):
        try:
            root = resolve_directory(self._get_directory())
            return baseline_path_for(root, self._get_baseline())
        except Exception:
            return None

    def _refresh_baseline(self) -> None:
        directory = self._get_directory()
        if not directory:
            self._baseline_state = "none"
            self.baseline_status_row.set_subtitle("No directory selected")
            self.baseline_icon.set_from_icon_name("dialog-question-symbolic")
            self.baseline_created_row.set_subtitle("—")
            self.baseline_files_row.set_subtitle("—")
            self.baseline_path_row.set_subtitle("—")
            self.baseline_root_row.set_subtitle("—")
            self.baseline_info_label.set_label("A baseline records the trusted SHA-256 hash of every file so later scans can detect changes.")
            self._update_hint()
            return

        try:
            root = resolve_directory(directory)
            path = baseline_path_for(root, self._get_baseline())
        except FimError as exc:
            self._baseline_state = "error"
            self.baseline_status_row.set_subtitle("Invalid directory")
            self.baseline_icon.set_from_icon_name("dialog-error-symbolic")
            self.baseline_info_label.set_label(str(exc))
            self._update_hint()
            return

        self.baseline_path_row.set_subtitle(str(path))
        self.baseline_root_row.set_subtitle(str(root))

        if not path.exists():
            self._baseline_state = "missing"
            self.baseline_status_row.set_subtitle("No baseline yet")
            self.baseline_icon.set_from_icon_name("dialog-warning-symbolic")
            self.baseline_created_row.set_subtitle("—")
            self.baseline_files_row.set_subtitle("—")
            self.baseline_info_label.set_label(f"Create a baseline at {path} to start monitoring this folder.")
            self._update_hint()
            return

        if path.is_dir():
            self._baseline_state = "error"
            self.baseline_status_row.set_subtitle("Baseline path is a directory")
            self.baseline_icon.set_from_icon_name("dialog-error-symbolic")
            self.baseline_info_label.set_label(f"Baseline path is a directory: {path}")
            self._update_hint()
            return

        try:
            stored = load_baseline(path)
            self._baseline_state = "ready"
            self.baseline_status_row.set_subtitle("Baseline ready")
            self.baseline_icon.set_from_icon_name("emblem-ok-symbolic")
            self.baseline_created_row.set_subtitle(self._format_date(stored.created))
            self.baseline_files_row.set_subtitle(f"{len(stored.files)} files")
            if str(root) != stored.root:
                self.baseline_info_label.set_label("This baseline was created for a different directory. Relative paths are still compared.")
            else:
                self.baseline_info_label.set_label("This baseline is the trusted reference. Run a check to detect drift.")
        except FimError as exc:
            self._baseline_state = "error"
            self.baseline_status_row.set_subtitle("Baseline is invalid")
            self.baseline_icon.set_from_icon_name("dialog-error-symbolic")
            self.baseline_created_row.set_subtitle("—")
            self.baseline_files_row.set_subtitle("—")
            self.baseline_info_label.set_label(str(exc))
        self._update_hint()

    def _create_baseline(self, _btn) -> None:
        if not self._get_directory():
            self.toast("Select a directory first")
            return

        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Create baseline?",
            body="The current file hashes will become the trusted reference for this directory.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("create", "Create")
        dialog.set_response_appearance("create", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("create")
        dialog.connect("response", self._on_create_response)
        dialog.present()

    def _on_create_response(self, dialog, response) -> None:
        if response != "create":
            return
        self._do_create_baseline(force=False)

    def _do_create_baseline(self, force: bool) -> None:
        self._set_busy(True)
        self.baseline_btn.set_label("Scanning..." if not force else "Replacing...")

        def task():
            try:
                stored, scan = create_baseline(
                    self._get_directory(),
                    baseline=self._get_baseline(),
                    excludes=self._get_excludes(),
                    force=force,
                )
                GLib.idle_add(lambda: self._on_baseline_created(stored, scan, None))
            except BaselineExistsError:
                GLib.idle_add(lambda: self._confirm_replace_baseline())
            except FimError as exc:
                GLib.idle_add(lambda: self._on_baseline_created(None, None, str(exc)))
            except Exception as exc:
                GLib.idle_add(lambda: self._on_baseline_created(None, None, str(exc)))

        import threading
        threading.Thread(target=task, daemon=True).start()

    def _confirm_replace_baseline(self) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Replace existing baseline?",
            body="A baseline already exists. Replace it with a fresh snapshot of the current state?",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("replace", "Replace")
        dialog.set_response_appearance("replace", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", lambda d, r: self._on_replace_response(r))
        dialog.present()

    def _on_replace_response(self, response) -> None:
        if response != "replace":
            self._set_busy(False)
            self.baseline_btn.set_label("Create Baseline")
            return
        self._do_create_baseline(force=True)

    def _on_baseline_created(self, stored, scan, error) -> None:
        self._set_busy(False)
        self.baseline_btn.set_label("Create Baseline")
        if error:
            self.toast(f"Error: {error}")
            return
        count = len(scan.files)
        self.toast(f"Baseline created for {count} { 'file' if count==1 else 'files' }")
        if scan.warnings:
            self.toast(f"{len(scan.warnings)} warning(s) during scan")
        self._refresh_baseline()

    # -- Check ------------------------------------------------------------

    def _run_check(self, _btn) -> None:
        if not self._get_directory():
            self.toast("Select a directory first")
            return
        self._set_busy(True)
        self.check_btn.set_label("Checking...")

        def task():
            try:
                outcome = check_integrity(
                    self._get_directory(),
                    baseline=self._get_baseline(),
                    excludes=self._get_excludes(),
                )
                report = self._outcome_to_report(outcome)
                GLib.idle_add(lambda: self._on_check_done(report, None))
            except FimError as exc:
                GLib.idle_add(lambda: self._on_check_done(None, str(exc)))
            except Exception as exc:
                GLib.idle_add(lambda: self._on_check_done(None, str(exc)))

        import threading
        threading.Thread(target=task, daemon=True).start()

    def _outcome_to_report(self, outcome) -> dict:
        from .report import report_as_dict
        report = report_as_dict(outcome.comparison, outcome.baseline, outcome.scan)
        report["has_changes"] = outcome.comparison.has_changes
        report["baseline"]["file_count"] = len(outcome.baseline.files)
        return report

    def _on_check_done(self, report, error) -> None:
        self._set_busy(False)
        self.check_btn.set_label("Run Check")
        if error:
            self.toast(f"Error: {error}")
            self.stack.set_visible_child_name("empty")
            return

        self._report = report
        self._render_report(report)
        self._add_to_history(report)
        self._refresh_baseline()

        if report.get("has_changes"):
            self.toast("Changes detected!")
        elif report.get("warnings"):
            self.toast("Check complete with warnings")
        else:
            self.toast("All files match baseline")

    def _render_report(self, report) -> None:
        summary = report.get("summary", {})
        modified = summary.get("modified", 0)
        added = summary.get("added", 0)
        deleted = summary.get("deleted", 0)
        unchanged = summary.get("unchanged", 0)

        getattr(self, "summary_modified_value").set_label(str(modified))
        getattr(self, "summary_added_value").set_label(str(added))
        getattr(self, "summary_deleted_value").set_label(str(deleted))
        getattr(self, "summary_unchanged_value").set_label(str(unchanged))
        self.summary_box.set_visible(True)

        # filters
        total = summary.get("total_changes", 0)
        self.filter_all.set_label(f"All {total}")
        self.filter_mod.set_label(f"Modified {modified}")
        self.filter_add.set_label(f"Added {added}")
        self.filter_del.set_label(f"Deleted {deleted}")
        self.filter_box.set_visible(True)
        scanned = report.get("scanned_files", 0)
        self.scan_meta_label.set_label(f"{scanned} files scanned")

        # warnings
        self._clear_box(self.warnings_box)
        warnings = report.get("warnings", [])
        if warnings:
            self.warnings_box.set_visible(True)
            for w in warnings:
                row = Adw.ActionRow()
                row.set_title("Warning")
                row.set_subtitle(w)
                img = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                img.set_css_classes(["warning"])
                row.add_prefix(img)
                row.set_activatable(False)
                self.warnings_box.append(row)
        else:
            self.warnings_box.set_visible(False)

        changes = report.get("changes", [])
        if not changes and not warnings:
            self.stack.set_visible_child_name("clean")
            return
        if not changes:
            self.stack.set_visible_child_name("clean")
            return

        self._render_changes_list(changes)
        self.stack.set_visible_child_name("list")

    def _render_changes_list(self, changes) -> None:
        while child := self.list_box.get_first_child():
            self.list_box.remove(child)

        filtered = []
        for c in changes:
            if self._filter_type == "all" or c.get("type") == self._filter_type:
                filtered.append(c)

        if not filtered and changes:
            row = Adw.ActionRow(title="No changes match this filter")
            row.set_activatable(False)
            self.list_box.append(row)
            return

        for change in filtered:
            ctype = change.get("type", "")
            path = change.get("path", "")
            row = Adw.ActionRow()
            row.set_title(path)
            row.set_subtitle(self._change_subtitle(change))

            if ctype == "modified":
                img = Gtk.Image.new_from_icon_name("document-edit-symbolic")
                img.set_css_classes(["warning"])
                row.add_prefix(img)
                row.get_style_context().add_class("change-modified")
            elif ctype == "added":
                img = Gtk.Image.new_from_icon_name("list-add-symbolic")
                img.set_css_classes(["success"])
                row.add_prefix(img)
                row.get_style_context().add_class("change-added")
            else:
                img = Gtk.Image.new_from_icon_name("list-remove-symbolic")
                img.set_css_classes(["danger"])
                row.add_prefix(img)
                row.get_style_context().add_class("change-deleted")

            badge = Gtk.Label(label=ctype.upper())
            badge.set_css_classes(["caption"])
            badge.set_margin_start(6)
            row.add_suffix(badge)
            row.set_activatable(False)
            self.list_box.append(row)

    def _change_subtitle(self, change) -> str:
        ctype = change.get("type")
        if ctype == "modified":
            before = change.get("before", {})
            after = change.get("after", {})
            return f"SHA-256: {self._short_hash(before.get('sha256',''))} → {self._short_hash(after.get('sha256',''))}  |  {self._fmt_size(before.get('size'))} → {self._fmt_size(after.get('size'))}"
        elif ctype == "added":
            after = change.get("after", {})
            return f"SHA-256: {self._short_hash(after.get('sha256',''))}  |  Size: {self._fmt_size(after.get('size'))}"
        else:
            before = change.get("before", {})
            return f"SHA-256: {self._short_hash(before.get('sha256',''))}  |  Size: {self._fmt_size(before.get('size'))}"

    def _short_hash(self, h) -> str:
        if not h: return "—"
        return h[:12] + "…" if len(h) > 12 else h

    def _fmt_size(self, size) -> str:
        if size is None: return "—"
        size = int(size)
        for unit in ("B","KiB","MiB","GiB"):
            if size < 1024 or unit == "GiB":
                if unit == "B": return f"{size} B"
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size} B"

    def _on_filter_toggled(self, btn, ftype) -> None:
        if btn.get_active():
            self._filter_type = ftype
            if self._report:
                self._render_changes_list(self._report.get("changes", []))

    def _format_date(self, created) -> str:
        try:
            dt = datetime.fromisoformat(str(created))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(created)

    # -- History ----------------------------------------------------------

    def _load_history(self) -> None:
        try:
            if self._history_file.exists():
                data = json.loads(self._history_file.read_text())
                self._history = [HistoryEntry(**h) for h in data if isinstance(h, dict)]
        except Exception:
            self._history = []

    def _save_history(self) -> None:
        try:
            data = [h.__dict__ for h in self._history]
            self._history_file.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def _add_to_history(self, report) -> None:
        summary = report.get("summary", {})
        entry = HistoryEntry(
            time=datetime.now().isoformat(),
            directory=report.get("root", ""),
            baseline=report.get("baseline", {}).get("path", ""),
            result="changes" if report.get("has_changes") else "clean",
            warnings=len(report.get("warnings", [])),
            modified=summary.get("modified", 0),
            added=summary.get("added", 0),
            deleted=summary.get("deleted", 0),
            unchanged=summary.get("unchanged", 0),
            scanned=report.get("scanned_files", 0),
        )
        self._history = [entry] + self._history[:14]
        self._save_history()
        self._refresh_history_ui()

    def _refresh_history_ui(self) -> None:
        while child := self.history_list.get_first_child():
            if child == self.history_empty_row:
                break
            self.history_list.remove(child)
        if not self._history:
            self.history_empty_row.set_visible(True)
            return
        self.history_empty_row.set_visible(False)
        for i, entry in enumerate(self._history):
            row = Adw.ActionRow()
            try:
                dt = datetime.fromisoformat(entry.time)
                ts = dt.strftime("%b %d %H:%M")
            except Exception:
                ts = entry.time[:16]
            row.set_title(os.path.basename(entry.directory) or entry.directory)
            row.set_subtitle(f"{ts}  •  {entry.modified}M/{entry.added}A/{entry.deleted}D")
            if entry.result == "changes":
                img = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                img.set_css_classes(["warning"])
                row.add_prefix(img)
            else:
                img = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                img.set_css_classes(["success"])
                row.add_prefix(img)
            row.set_activatable(True)
            row._history_index = i
            self.history_list.append(row)

    def _load_history_entry(self, listbox, row) -> None:
        if not hasattr(row, "_history_index"):
            return
        entry = self._history[row._history_index]
        self.directory_entry.set_text(entry.directory)
        self.baseline_entry.set_text(entry.baseline)
        self._refresh_baseline()
        self.toast("Target loaded from history")

    def _clear_history(self, _btn) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Clear history?",
            body="This will remove all recent checks from this list.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("clear", "Clear")
        dialog.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", self._on_clear_history_response)
        dialog.present()

    def _on_clear_history_response(self, dialog, response) -> None:
        if response != "clear":
            return
        self._history = []
        self._save_history()
        self._refresh_history_ui()
        self.toast("History cleared")

    def _clear_box(self, box) -> None:
        while child := box.get_first_child():
            box.remove(child)


def main():
    Adw.init()
    app = FimApp()
    return app.run(None)


if __name__ == "__main__":
    raise SystemExit(main())
