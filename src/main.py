#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import platform
import socket
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import netifaces

from PyQt5 import QtCore, QtGui, QtWidgets, QtPrintSupport


# -------------------
# Data model
# -------------------

@dataclass
class InterfaceRow:
    name: str
    mac: str
    ipv4: str
    ipv6: str
    up: bool
    speed_mbps: Optional[int]


@dataclass
class ConnRow:
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    pid: Optional[int]
    proc: str


@dataclass
class RouteRow:
    destination: str
    gateway: str
    iface: str
    metric: Optional[int]


@dataclass
class ArpRow:
    ip: str
    mac: str
    iface: str


@dataclass
class DnsData:
    nameservers: List[str]
    search: List[str]
    options: Dict[str, Any]


@dataclass
class Snapshot:
    created_utc: str
    host: Dict[str, Any]
    interfaces: List[InterfaceRow]
    connections: List[ConnRow]
    routes: List[RouteRow]
    arp: List[ArpRow]
    dns: DnsData
    sha256: Optional[str] = None

    def _base_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("sha256", None)
        return d

    def to_json_with_sha(self) -> str:
        base = self._base_dict()
        payload = json.dumps(base, indent=2, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        base["sha256"] = digest
        self.sha256 = digest
        return json.dumps(base, indent=2, sort_keys=True)


# -------------------
# Main Window
# -------------------

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Analysis Tool")
        self.resize(1000, 700)

        self.snapshot: Optional[Snapshot] = None

        self._build_ui()

    # ---------- UI setup ----------

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        main_layout = QtWidgets.QVBoxLayout(central)

        # Top buttons
        btn_row = QtWidgets.QHBoxLayout()
        self.btn_scan = QtWidgets.QPushButton("Scan Network")
        self.btn_export_json = QtWidgets.QPushButton("Export JSON")
        self.btn_export_pdf = QtWidgets.QPushButton("Export PDF")

        btn_row.addWidget(self.btn_scan)
        btn_row.addWidget(self.btn_export_json)
        btn_row.addWidget(self.btn_export_pdf)
        btn_row.addStretch(1)

        main_layout.addLayout(btn_row)

        # Host info label
        self.lbl_host = QtWidgets.QLabel("Host: -")
        main_layout.addWidget(self.lbl_host)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        main_layout.addWidget(self.tabs, 1)

        self.tab_ifaces = self._make_table(
            ["Name", "MAC", "IPv4", "IPv6", "Up", "Speed (Mbps)"]
        )
        self.tab_conns = self._make_table(
            ["Proto", "Laddr", "Lport", "Raddr", "Rport", "Status", "PID", "Process"]
        )
        self.tab_routes = self._make_table(
            ["Destination", "Gateway", "Interface", "Metric"]
        )
        self.tab_dns = self._make_table(
            ["Nameservers", "Search Domains", "Options (JSON)"]
        )
        self.tab_arp = self._make_table(
            ["IP", "MAC", "Interface"]
        )

        self.tabs.addTab(self.tab_ifaces["widget"], "Interfaces")
        self.tabs.addTab(self.tab_conns["widget"], "Connections")
        self.tabs.addTab(self.tab_routes["widget"], "Routes")
        self.tabs.addTab(self.tab_dns["widget"], "DNS")
        self.tabs.addTab(self.tab_arp["widget"], "ARP")

        # Status bar
        self.statusBar().showMessage("Ready")

        # Wire buttons
        self.btn_scan.clicked.connect(self.on_scan_clicked)
        self.btn_export_json.clicked.connect(self.on_export_json_clicked)
        self.btn_export_pdf.clicked.connect(self.on_export_pdf_clicked)

    def _make_table(self, headers: List[str]) -> Dict[str, Any]:
        model = QtGui.QStandardItemModel(0, len(headers))
        model.setHorizontalHeaderLabels(headers)

        view = QtWidgets.QTableView()
        view.setModel(model)
        view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        view.setSortingEnabled(True)
        view.horizontalHeader().setStretchLastSection(True)
        view.verticalHeader().setVisible(False)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.addWidget(view)

        return {"widget": container, "model": model, "view": view}

    # ---------- Scan ----------

    def on_scan_clicked(self):
        self.statusBar().showMessage("Scanning…")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
        try:
            snap = self.collect_snapshot()
            self.snapshot = snap
            self.populate_ui_from_snapshot(snap)
            self.statusBar().showMessage("Scan complete")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Scan failed", str(e))
            self.statusBar().showMessage("Scan failed")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

    def collect_snapshot(self) -> Snapshot:
        host = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": platform.platform(),
            "os": platform.system(),
            "os_release": platform.release(),
        }
        interfaces = self._collect_interfaces()
        connections = self._collect_connections()
        routes = self._collect_routes()
        arp = self._collect_arp()
        dns = self._collect_dns()

        return Snapshot(
            created_utc=datetime.now(timezone.utc).isoformat(),
            host=host,
            interfaces=interfaces,
            connections=connections,
            routes=routes,
            arp=arp,
            dns=dns,
        )

    def _collect_interfaces(self) -> List[InterfaceRow]:
        out: List[InterfaceRow] = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for name, info in addrs.items():
            mac = ""
            ipv4s: List[str] = []
            ipv6s: List[str] = []

            for a in info:
                fam = getattr(a, "family", None)
                if fam == psutil.AF_LINK:
                    mac = a.address or ""
                elif fam == socket.AF_INET:
                    ipv4s.append(a.address)
                elif fam == socket.AF_INET6:
                    ipv6s.append(a.address.split("%")[0])

            st = stats.get(name)
            out.append(
                InterfaceRow(
                    name=name,
                    mac=mac,
                    ipv4=", ".join(ipv4s),
                    ipv6=", ".join(ipv6s),
                    up=bool(st.isup) if st else False,
                    speed_mbps=getattr(st, "speed", None) if st else None,
                )
            )
        return out

    def _collect_connections(self) -> List[ConnRow]:
        rows: List[ConnRow] = []

        # TCP
        for c in psutil.net_connections(kind="tcp"):
            laddr = c.laddr.ip if c.laddr else ""
            lport = c.laddr.port if c.laddr else 0
            raddr = c.raddr.ip if c.raddr else ""
            rport = c.raddr.port if c.raddr else 0
            pid = c.pid
            pname = ""
            if pid:
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = ""
            rows.append(
                ConnRow(
                    proto="TCP",
                    laddr=laddr,
                    lport=lport,
                    raddr=raddr,
                    rport=rport,
                    status=c.status or "",
                    pid=pid,
                    proc=pname,
                )
            )

        # UDP
        for c in psutil.net_connections(kind="udp"):
            laddr = c.laddr.ip if c.laddr else ""
            lport = c.laddr.port if c.laddr else 0
            pid = c.pid
            pname = ""
            if pid:
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = ""
            rows.append(
                ConnRow(
                    proto="UDP",
                    laddr=laddr,
                    lport=lport,
                    raddr="",
                    rport=0,
                    status="",
                    pid=pid,
                    proc=pname,
                )
            )
        return rows

    def _collect_routes(self) -> List[RouteRow]:
        rows: List[RouteRow] = []

        # Default gateways via netifaces
        try:
            gws = netifaces.gateways()
            default = gws.get("default", {})
            for _, (gw, iface) in default.items():
                rows.append(
                    RouteRow(
                        destination="0.0.0.0/0",
                        gateway=str(gw),
                        iface=str(iface),
                        metric=None,
                    )
                )
        except Exception:
            pass

        # Linux /proc/net/route (best-effort extra info)
        route_path = Path("/proc/net/route")
        if route_path.exists():
            with route_path.open() as f:
                next(f)  # header
                for line in f:
                    parts = line.strip().split("\t")
                    if len(parts) >= 8:
                        iface = parts[0]
                        dest_hex = parts[1]
                        gw_hex = parts[2]
                        metric = int(parts[6]) if parts[6].isdigit() else None
                        destination = self._hex_to_ipv4(dest_hex)
                        gateway = self._hex_to_ipv4(gw_hex)
                        rows.append(
                            RouteRow(
                                destination=destination,
                                gateway=gateway,
                                iface=iface,
                                metric=metric,
                            )
                        )
        return rows

    def _collect_arp(self) -> List[ArpRow]:
        rows: List[ArpRow] = []
        path = Path("/proc/net/arp")
        if path.exists():
            with path.open() as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 6:
                        ip, _hwtype, _flags, mac, _mask, iface = cols[:6]
                        rows.append(ArpRow(ip=ip, mac=mac, iface=iface))
        return rows

    def _collect_dns(self) -> DnsData:
        nameservers: List[str] = []
        search: List[str] = []
        options: Dict[str, Any] = {}

        path = Path("/etc/resolv.conf")
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])
                elif line.startswith("search"):
                    parts = line.split()
                    search.extend(parts[1:])
                elif line.startswith("options"):
                    parts = line.split()[1:]
                    for p in parts:
                        if "=" in p:
                            k, v = p.split("=", 1)
                            options[k] = v
                        else:
                            options[p] = True

        return DnsData(nameservers=nameservers, search=search, options=options)

    def _hex_to_ipv4(self, hex_str: str) -> str:
        try:
            b = bytes.fromhex(hex_str)
            if len(b) == 4:
                return ".".join(str(x) for x in b[::-1])  # little endian
        except Exception:
            pass
        return "-"

    # ---------- Populate UI ----------

    def populate_ui_from_snapshot(self, snap: Snapshot):
        self.lbl_host.setText(
            f"Host: {snap.host.get('hostname','-')} | {snap.host.get('platform','-')}"
        )

        # clear all models
        for tab in (
            self.tab_ifaces,
            self.tab_conns,
            self.tab_routes,
            self.tab_dns,
            self.tab_arp,
        ):
            tab["model"].removeRows(0, tab["model"].rowCount())

        # Interfaces
        for r in snap.interfaces:
            self._add_row(
                self.tab_ifaces["model"],
                [
                    r.name,
                    r.mac,
                    r.ipv4,
                    r.ipv6,
                    "Yes" if r.up else "No",
                    r.speed_mbps if r.speed_mbps is not None else "-",
                ],
            )

        # Connections
        for c in snap.connections:
            self._add_row(
                self.tab_conns["model"],
                [
                    c.proto,
                    c.laddr,
                    c.lport,
                    c.raddr,
                    c.rport,
                    c.status,
                    c.pid if c.pid is not None else "-",
                    c.proc,
                ],
            )

        # Routes
        for r in snap.routes:
            self._add_row(
                self.tab_routes["model"],
                [
                    r.destination,
                    r.gateway,
                    r.iface,
                    r.metric if r.metric is not None else "-",
                ],
            )

        # DNS (single summary row)
        dns = snap.dns
        self._add_row(
            self.tab_dns["model"],
            [
                ", ".join(dns.nameservers),
                ", ".join(dns.search),
                json.dumps(dns.options, sort_keys=True),
            ],
        )

        # ARP
        for a in snap.arp:
            self._add_row(
                self.tab_arp["model"],
                [a.ip, a.mac, a.iface],
            )

    def _add_row(self, model: QtGui.QStandardItemModel, values: List[Any]):
        items = [QtGui.QStandardItem(str(v)) for v in values]
        for it in items:
            it.setEditable(False)
        model.appendRow(items)

    # ---------- Export JSON ----------

    def on_export_json_clicked(self):
        if not self.snapshot:
            QtWidgets.QMessageBox.information(
                self, "No data", "Run a scan first."
            )
            return

        export_dir = Path("Exports").resolve()
        export_dir.mkdir(exist_ok=True)

        default_name = f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        file_path = export_dir / default_name

        data = self.snapshot.to_json_with_sha()
        file_path.write_text(data, encoding="utf-8")

        QtGui.QDesktopServices.openUrl(
            QtCore.QUrl.fromLocalFile(str(export_dir))
        )
        self.statusBar().showMessage(f"Saved JSON: {file_path}")

    # ---------- Export PDF ----------

    def on_export_pdf_clicked(self):
        if not self.snapshot:
            QtWidgets.QMessageBox.information(
                self, "No data", "Run a scan first."
            )
            return

        export_dir = Path("Exports").resolve()
        export_dir.mkdir(exist_ok=True)

        default_name = f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path = export_dir / default_name

        self._render_pdf(str(file_path))

        # Open the folder where it was saved
        QtGui.QDesktopServices.openUrl(
            QtCore.QUrl.fromLocalFile(str(export_dir))
        )
        self.statusBar().showMessage(f"Saved PDF: {file_path}")

    def _render_pdf(self, out_path: str):
        snap = self.snapshot
        if not snap:
            return

        html_parts: List[str] = []

        html_parts.append("<h2>Network Snapshot Report</h2>")
        html_parts.append(f"<p><b>Created (UTC):</b> {snap.created_utc}</p>")
        html_parts.append(
            f"<p><b>Host:</b> {self._e(snap.host.get('hostname','-'))} | "
            f"{self._e(snap.host.get('platform','-'))}</p>"
        )

        # Interfaces table
        html_parts.append("<h3>Interfaces</h3>")
        html_parts.append(
            "<table border='1' cellspacing='0' cellpadding='3'>"
            "<tr><th>Name</th><th>MAC</th><th>IPv4</th><th>IPv6</th>"
            "<th>Up</th><th>Speed (Mbps)</th></tr>"
        )
        for r in snap.interfaces:
            html_parts.append(
                "<tr>"
                f"<td>{self._e(r.name)}</td>"
                f"<td>{self._e(r.mac)}</td>"
                f"<td>{self._e(r.ipv4)}</td>"
                f"<td>{self._e(r.ipv6)}</td>"
                f"<td>{'Yes' if r.up else 'No'}</td>"
                f"<td>{self._e(r.speed_mbps if r.speed_mbps is not None else '-')}</td>"
                "</tr>"
            )
        html_parts.append("</table>")

        # Connections
        html_parts.append("<h3>Connections</h3>")
        html_parts.append(
            "<table border='1' cellspacing='0' cellpadding='3'>"
            "<tr><th>Proto</th><th>Laddr</th><th>Lport</th>"
            "<th>Raddr</th><th>Rport</th><th>Status</th><th>PID</th><th>Process</th></tr>"
        )
        for c in snap.connections:
            html_parts.append(
                "<tr>"
                f"<td>{self._e(c.proto)}</td>"
                f"<td>{self._e(c.laddr)}</td>"
                f"<td>{c.lport}</td>"
                f"<td>{self._e(c.raddr)}</td>"
                f"<td>{c.rport}</td>"
                f"<td>{self._e(c.status)}</td>"
                f"<td>{self._e(c.pid if c.pid is not None else '-')}</td>"
                f"<td>{self._e(c.proc)}</td>"
                "</tr>"
            )
        html_parts.append("</table>")

        # Routes
        html_parts.append("<h3>Routes</h3>")
        html_parts.append(
            "<table border='1' cellspacing='0' cellpadding='3'>"
            "<tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th></tr>"
        )
        for r in snap.routes:
            html_parts.append(
                "<tr>"
                f"<td>{self._e(r.destination)}</td>"
                f"<td>{self._e(r.gateway)}</td>"
                f"<td>{self._e(r.iface)}</td>"
                f"<td>{self._e(r.metric if r.metric is not None else '-')}</td>"
                "</tr>"
            )
        html_parts.append("</table>")

        # DNS
        html_parts.append("<h3>DNS</h3>")
        html_parts.append(
            "<p>"
            f"<b>Nameservers:</b> {self._e(', '.join(snap.dns.nameservers))}<br>"
            f"<b>Search:</b> {self._e(', '.join(snap.dns.search))}<br>"
            f"<b>Options:</b> {self._e(json.dumps(snap.dns.options, sort_keys=True))}"
            "</p>"
        )

        # ARP
        html_parts.append("<h3>ARP</h3>")
        html_parts.append(
            "<table border='1' cellspacing='0' cellpadding='3'>"
            "<tr><th>IP</th><th>MAC</th><th>Interface</th></tr>"
        )
        for a in snap.arp:
            html_parts.append(
                "<tr>"
                f"<td>{self._e(a.ip)}</td>"
                f"<td>{self._e(a.mac)}</td>"
                f"<td>{self._e(a.iface)}</td>"
                "</tr>"
            )
        html_parts.append("</table>")

        if snap.sha256:
            html_parts.append(
                f"<p><b>SHA-256:</b> {self._e(snap.sha256)}</p>"
            )

        html = "\n".join(html_parts)

        doc = QtGui.QTextDocument()
        doc.setHtml(html)   # IMPORTANT: render as HTML, not plain text

        printer = QtPrintSupport.QPrinter(QtPrintSupport.QPrinter.HighResolution)
        printer.setOutputFormat(QtPrintSupport.QPrinter.PdfFormat)
        printer.setOutputFileName(out_path)
        doc.print_(printer)

    def _e(self, s: Any) -> str:
        text = "" if s is None else str(s)
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )


# -------------------
# Entry point
# -------------------

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
