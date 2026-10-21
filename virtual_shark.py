"""
VirtualShark Pro - Gestor de Capturas VirtualBox, Topología Cisco y Simulador de Pings
Soporte para Múltiples Redes y Topologías Independientes / Laboratorios Separados.
"""

import os
import sys
import time
import shutil
import math
import threading
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


# ==============================================================================
# CONFIGURACIÓN Y ESTILOS
# ==============================================================================
APP_TITLE = "VirtualShark Pro - Topología Cisco & Wireshark para VirtualBox"
DEFAULT_VM = "cliente1"
DOCS_DIR = os.path.join(os.path.expanduser("~"), "Documents")

COLOR_BG = "#0f172a"            # Slate 900
COLOR_PANEL = "#1e293b"         # Slate 800
COLOR_CARD = "#334155"          # Slate 700
COLOR_TEXT = "#f8fafc"          # Slate 50
COLOR_MUTED = "#94a3b8"         # Slate 400
COLOR_BORDER = "#475569"        # Slate 600

# Colores de Equipos y Redes (Estilo Cisco Packet Tracer)
COLOR_ROUTER = "#0284c7"        # Azul Cisco
COLOR_SWITCH = "#10b981"        # Verde Esmeralda Switch
COLOR_PC = "#6366f1"            # Indigo Clientes
COLOR_SERVER = "#8b5cf6"        # Violeta Servidores
COLOR_CLOUD = "#06b6d4"         # Cian Nube NAT
COLOR_CABLE = "#64748b"         # Cable gris
COLOR_CABLE_ACTIVE = "#22c55e"  # Cable activo verde
COLOR_PACKET = "#f59e0b"        # Paquete ámbar brillante
COLOR_SUCCESS = "#22c55e"
COLOR_DANGER = "#ef4444"
COLOR_WARNING = "#f59e0b"


# ==============================================================================
# GESTOR DE VIRTUALBOX (VBoxManage)
# ==============================================================================
class VirtualBoxManager:
    """Administra comandos VBoxManage, inventario de VMs y topologías independientes."""

    def __init__(self):
        self.vboxmanage_path = self._find_vboxmanage()

    def _find_vboxmanage(self) -> str:
        candidates = [
            r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
            os.path.join(os.environ.get("VBOX_MSI_INSTALL_PATH", ""), "VBoxManage.exe"),
            os.path.join(os.environ.get("VBOX_INSTALL_PATH", ""), "VBoxManage.exe"),
        ]
        for c in candidates:
            if c and os.path.exists(c):
                return c

        which = shutil.which("VBoxManage")
        if which and os.path.exists(which):
            return which

        return "VBoxManage.exe"

    def is_available(self) -> bool:
        if os.path.isabs(self.vboxmanage_path):
            return os.path.exists(self.vboxmanage_path)
        return shutil.which(self.vboxmanage_path) is not None

    def run_cmd(self, args: list) -> tuple[int, str, str]:
        cmd = [self.vboxmanage_path] + args
        try:
            startupinfo = None
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                startupinfo=startupinfo,
            )
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return -1, "", str(e)

    def list_vms(self) -> list[str]:
        code, stdout, _ = self.run_cmd(["list", "vms"])
        vms = []
        if code == 0:
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith('"') and '"' in line[1:]:
                    end_idx = line.find('"', 1)
                    vms.append(line[1:end_idx])
        return vms

    def get_vm_state(self, vm_name: str) -> dict:
        code, stdout, _ = self.run_cmd(["showvminfo", vm_name, "--machinereadable"])
        raw = {}
        info = {
            "state": "unknown",
            "adapters": {},
            "raw": raw
        }
        if code == 0:
            for line in stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    raw[k.strip()] = v.strip().strip('"')

            info["state"] = raw.get("VMState", "unknown").lower()

            for idx in range(1, 9):
                mode = raw.get(f"nic{idx}")
                if mode and mode != "none":
                    if mode == "intnet":
                        net_name = raw.get(f"intnet{idx}") or "intnet"
                    elif mode == "hostonly":
                        net_name = raw.get(f"hostonlyadapter{idx}") or "HostOnly"
                    elif mode == "nat":
                        net_name = "NAT"
                    elif mode == "bridged":
                        net_name = raw.get(f"bridgeadapter{idx}") or "Bridged"
                    else:
                        net_name = mode.upper()

                    mac = raw.get(f"macaddress{idx}")
                    cable = raw.get(f"cableconnected{idx}", "on") == "on"
                    info["adapters"][idx] = {
                        "mode": mode,
                        "net_name": net_name,
                        "mac": mac,
                        "cable": cable
                    }
        return info

    def is_vm_running(self, vm_name: str) -> bool:
        return self.get_vm_state(vm_name)["state"] == "running"

    def start_vm(self, vm_name: str, headless: bool = False) -> tuple[bool, str]:
        vm_type = "headless" if headless else "gui"
        code, stdout, stderr = self.run_cmd(["startvm", vm_name, "--type", vm_type])
        if code == 0:
            return True, f"Máquina '{vm_name}' iniciada."
        return False, stderr.strip() or stdout.strip()

    def stop_vm(self, vm_name: str) -> tuple[bool, str]:
        code, stdout, stderr = self.run_cmd(["controlvm", vm_name, "acpipowerbutton"])
        if code == 0:
            return True, f"Señal de apagado enviada a '{vm_name}'."
        return False, stderr.strip() or stdout.strip()

    def start_nic_trace(self, vm_name: str, pcap_path: str, adapter: int = 1) -> tuple[bool, str]:
        is_running = self.is_vm_running(vm_name)
        if is_running:
            code1, out1, err1 = self.run_cmd(["controlvm", vm_name, f"nictracefile{adapter}", pcap_path])
            if code1 != 0:
                return False, f"Error al asignar archivo: {err1 or out1}"
            code2, out2, err2 = self.run_cmd(["controlvm", vm_name, f"nictrace{adapter}", "on"])
            if code2 != 0:
                return False, f"Error al activar captura: {err2 or out2}"
            return True, f"Captura activa en tiempo real ({vm_name}, Adaptador {adapter})."
        else:
            code, out, err = self.run_cmd([
                "modifyvm", vm_name,
                f"--nic-trace{adapter}=on",
                f"--nic-trace-file{adapter}={pcap_path}"
            ])
            if code != 0:
                return False, f"Error al configurar captura previa: {err or out}"
            return True, f"Captura configurada en VM (iniciará al arrancar Adaptador {adapter})."

    def stop_nic_trace(self, vm_name: str, adapter: int = 1) -> tuple[bool, str]:
        if self.is_vm_running(vm_name):
            code, out, err = self.run_cmd(["controlvm", vm_name, f"nictrace{adapter}", "off"])
            return (code == 0), (f"Captura detenida en Adaptador {adapter}." if code == 0 else (err or out))
        else:
            code, out, err = self.run_cmd([
                "modifyvm", vm_name,
                f"--nic-trace{adapter}=off",
                f"--nic-trace-file{adapter}="
            ])
            return (code == 0), (f"Captura cancelada en VM apagada." if code == 0 else (err or out))

    def detect_topology_projects(self) -> list[dict]:
        """
        Analiza todas las VMs y agrupa las máquinas que están conectadas entre sí
        en 'Topologías / Proyectos Independientes' (Componentes Conexos).
        """
        all_vms = self.list_vms()
        vm_networks = {}

        for vm in all_vms:
            info = self.get_vm_state(vm)
            nets = set()
            for idx, ad in info["adapters"].items():
                mode = ad["mode"]
                name = ad["net_name"]
                if mode in ("intnet", "hostonly", "bridged"):
                    nets.add((mode, name))
            vm_networks[vm] = nets

        # Grafo de adyacencia (dos VMs están conectadas si comparten switch interno o hostonly)
        adj = defaultdict(set)
        for v1 in all_vms:
            for v2 in all_vms:
                if v1 != v2:
                    shared = vm_networks[v1].intersection(vm_networks[v2])
                    if shared:
                        adj[v1].add(v2)
                        adj[v2].add(v1)

        visited = set()
        projects = []

        # Ordenar para que el laboratorio principal con clientes/router quede primero
        for vm in all_vms:
            if vm not in visited:
                comp = []
                queue = [vm]
                visited.add(vm)
                while queue:
                    curr = queue.pop(0)
                    comp.append(curr)
                    for nxt in adj[curr]:
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append(nxt)

                # Extraer nombres de switches/redes en este componente
                nets_in_comp = []
                for v in comp:
                    for mode, name in vm_networks[v]:
                        if name not in nets_in_comp:
                            nets_in_comp.append(name)

                # Título descriptivo para el proyecto
                if nets_in_comp:
                    nets_str = ", ".join(nets_in_comp)
                    title = f"📁 Red: {nets_str} ({len(comp)} VMs: {', '.join(comp[:3])}{'...' if len(comp)>3 else ''})"
                else:
                    title = f"📁 VM Aislada: {comp[0]}"

                projects.append({
                    "id": f"proj_{len(projects)}",
                    "title": title,
                    "nets": nets_in_comp,
                    "vms": comp
                })

        # Mover al principio el proyecto que contenga 'cliente1' o 'Router_Linux'
        projects.sort(key=lambda p: 0 if any(k in p["vms"] for k in ("cliente1", "Router_Linux")) else 1)

        return projects

    def scan_full_topology(self, filter_vms: list[str] | None = None) -> dict:
        """
        Genera la estructura de topología (nodos, switches, nubes) para las VMs solicitadas.
        """
        all_vms = self.list_vms()
        if filter_vms:
            target_vms = [v for v in all_vms if v in filter_vms]
        else:
            target_vms = all_vms

        topology = {
            "vms": {},
            "switches": {},     # Redes intnet y hostonly
            "nat_clouds": {},   # Redes NAT
        }

        for vm in target_vms:
            info = self.get_vm_state(vm)
            vm_lower = vm.lower()
            if "router" in vm_lower or "gw" in vm_lower:
                device_type = "router"
            elif "server" in vm_lower or "zabbix" in vm_lower or "win" in vm_lower:
                device_type = "server"
            else:
                device_type = "pc"

            topology["vms"][vm] = {
                "name": vm,
                "type": device_type,
                "state": info["state"],
                "adapters": info["adapters"]
            }

            for idx, ad in info["adapters"].items():
                mode = ad["mode"]
                net_name = ad["net_name"]

                if mode in ("intnet", "hostonly", "bridged"):
                    sw_key = f"{mode.upper()}:{net_name}"
                    if sw_key not in topology["switches"]:
                        topology["switches"][sw_key] = {
                            "key": sw_key,
                            "name": net_name,
                            "type": "switch",
                            "mode": mode,
                            "ports": []
                        }
                    topology["switches"][sw_key]["ports"].append({
                        "vm": vm,
                        "adapter": idx,
                        "mac": ad["mac"],
                        "cable": ad["cable"]
                    })
                elif mode == "nat":
                    if "NAT" not in topology["nat_clouds"]:
                        topology["nat_clouds"]["NAT"] = {
                            "name": "Internet / NAT",
                            "type": "cloud",
                            "ports": []
                        }
                    topology["nat_clouds"]["NAT"]["ports"].append({
                        "vm": vm,
                        "adapter": idx,
                        "mac": ad["mac"],
                        "cable": ad["cable"]
                    })

        return topology


# ==============================================================================
# GESTOR DE WIRESHARK
# ==============================================================================
class WiresharkManager:
    def __init__(self):
        self.wireshark_path = self._find_wireshark()

    def _find_wireshark(self) -> str | None:
        candidates = [
            r"C:\Program Files\Wireshark\Wireshark.exe",
            r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        which = shutil.which("wireshark")
        if which and os.path.exists(which):
            return which
        return None

    def is_available(self) -> bool:
        return self.wireshark_path is not None

    def open_pcap(self, pcap_path: str) -> tuple[bool, str]:
        if not os.path.exists(pcap_path):
            return False, f"El archivo '{pcap_path}' no existe."
        try:
            if self.wireshark_path and os.path.exists(self.wireshark_path):
                subprocess.Popen([self.wireshark_path, pcap_path])
                return True, f"Wireshark abierto con: {os.path.basename(pcap_path)}"
            else:
                os.startfile(pcap_path)
                return True, "Archivo abierto con la aplicación predeterminada."
        except Exception as e:
            return False, f"Error al abrir Wireshark: {e}"


# ==============================================================================
# GESTOR DE ARCHIVOS .PCAP
# ==============================================================================
class PcapFileManager:
    def __init__(self, directory: str = DOCS_DIR):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

    def generate_filename(self, vm_name: str = "cliente1") -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return os.path.join(self.directory, f"captura_{vm_name}_{timestamp}.pcap")

    def scan_files(self) -> list[dict]:
        results = []
        if not os.path.exists(self.directory):
            return results
        try:
            with os.scandir(self.directory) as entries:
                for entry in entries:
                    if entry.is_file() and entry.name.lower().endswith((".pcap", ".pcapng")):
                        try:
                            stat = entry.stat()
                            mtime = stat.st_mtime
                            dt_mtime = datetime.fromtimestamp(mtime)
                            results.append({
                                "name": entry.name,
                                "path": entry.path,
                                "size_bytes": stat.st_size,
                                "size_fmt": self._format_size(stat.st_size),
                                "mtime": mtime,
                                "datetime_fmt": dt_mtime.strftime("%d/%m/%Y %H:%M:%S"),
                            })
                        except OSError:
                            continue
        except Exception:
            pass
        results.sort(key=lambda x: x["mtime"], reverse=True)
        return results

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def delete_file(self, filepath: str) -> tuple[bool, str]:
        if not os.path.exists(filepath):
            return False, "El archivo ya no existe."
        try:
            os.remove(filepath)
            return True, f"Archivo '{os.path.basename(filepath)}' eliminado."
        except Exception as e:
            return False, f"Error al eliminar: {e}"


# ==============================================================================
# MOTOR DE ENRUTAMIENTO Y SIMULACIÓN DE PINGS
# ==============================================================================
class NetworkRoutingEngine:
    @staticmethod
    def analyze_ping(src_vm: str, dst_vm: str, topology: dict) -> dict:
        vms = topology.get("vms", {})
        if src_vm not in vms or dst_vm not in vms:
            return {
                "success": False,
                "type": "INVALID",
                "message": "Una de las máquinas seleccionadas no está presente en la topología activa.",
                "path": []
            }

        if src_vm == dst_vm:
            return {
                "success": True,
                "type": "LOOPBACK",
                "message": f"Loopback local (127.0.0.1). {src_vm} responde a sí mismo instantáneamente.",
                "path": [src_vm]
            }

        src_info = vms[src_vm]
        dst_info = vms[dst_vm]

        # 1. Verificar Capa 2 (Switch Virtual compartido intnet o hostonly)
        src_nets = {f"{ad['mode'].upper()}:{ad['net_name']}": (idx, ad['net_name']) for idx, ad in src_info["adapters"].items() if ad["mode"] in ("intnet", "hostonly")}
        dst_nets = {f"{ad['mode'].upper()}:{ad['net_name']}": (idx, ad['net_name']) for idx, ad in dst_info["adapters"].items() if ad["mode"] in ("intnet", "hostonly")}

        shared_switches = set(src_nets.keys()).intersection(set(dst_nets.keys()))
        if shared_switches:
            sw_key = list(shared_switches)[0]
            src_nic, net_name = src_nets[sw_key]
            dst_nic, _ = dst_nets[sw_key]
            return {
                "success": True,
                "type": "L2_DIRECT",
                "switch": net_name,
                "message": f"Conexión Directa en Capa 2 a través del Switch '{net_name}'. Mismo segmento de difusión. No requiere router.",
                "path": [src_vm, f"SWITCH:{sw_key}", dst_vm],
                "hops": [
                    f"1. {src_vm} (nic{src_nic}) transmite trama Ethernet hacia switch '{net_name}'.",
                    f"2. Switch '{net_name}' conmuta la trama por MAC hacia {dst_vm} (nic{dst_nic}).",
                    f"3. {dst_vm} recibe y responde ICMP Echo Reply."
                ]
            }

        # 2. Verificar Enrutamiento Capa 3
        routers = [v for v, data in vms.items() if data["type"] == "router" or "router" in v.lower()]
        for r_name in routers:
            r_info = vms[r_name]
            r_nets = {f"{ad['mode'].upper()}:{ad['net_name']}": (idx, ad['net_name']) for idx, ad in r_info["adapters"].items() if ad["mode"] in ("intnet", "hostonly")}

            src_r_shared = set(src_nets.keys()).intersection(set(r_nets.keys()))
            dst_r_shared = set(dst_nets.keys()).intersection(set(r_nets.keys()))

            if src_r_shared and dst_r_shared:
                sw_src = list(src_r_shared)[0]
                sw_dst = list(dst_r_shared)[0]
                _, name_src = src_nets[sw_src]
                _, name_dst = dst_nets[sw_dst]

                is_r_running = (r_info["state"] == "running")
                msg = (
                    f"Conexión Enrutada en Capa 3 a través de '{r_name}'.\n"
                    f"• {src_vm} está en [{name_src}].\n"
                    f"• {dst_vm} está en [{name_dst}].\n"
                    f"• '{r_name}' enruta paquetes entre ambos segmentos."
                )
                if not is_r_running:
                    msg += f"\n⚠️ ATENCIÓN: '{r_name}' está APAGADO. El ping fallará hasta que se encienda el router."

                return {
                    "success": True,
                    "type": "L3_ROUTED",
                    "router": r_name,
                    "src_net": name_src,
                    "dst_net": name_dst,
                    "router_running": is_r_running,
                    "message": msg,
                    "path": [src_vm, f"SWITCH:{sw_src}", r_name, f"SWITCH:{sw_dst}", dst_vm],
                    "hops": [
                        f"1. {src_vm} envía paquete al Gateway '{r_name}' vía '{name_src}'.",
                        f"2. Switch '{name_src}' entrega paquete a '{r_name}'.",
                        f"3. '{r_name}' procesa cabecera IP y conmuta hacia '{name_dst}'.",
                        f"4. Switch '{name_dst}' entrega el paquete a {dst_vm}.",
                        f"5. {dst_vm} responde con ICMP Echo Reply."
                    ]
                }

        # 3. Sin ruta
        return {
            "success": False,
            "type": "UNREACHABLE",
            "message": f"Destino inalcanzable (Destination Host Unreachable). No existe switch compartido ni router configurado entre {src_vm} y {dst_vm}. Son topologías aisladas.",
            "path": [src_vm, dst_vm],
            "hops": [
                f"1. {src_vm} intenta resolver ARP para la red de destino.",
                f"2. No se encuentra Gateway predeterminado ni enlace común hacia {dst_vm}.",
                f"3. Paquete descartado (Redes totalmente independientes)."
            ]
        }


# ==============================================================================
# APLICACIÓN PRINCIPAL (VIRTUALSHARK PRO)
# ==============================================================================
class VirtualSharkProApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.vbox = VirtualBoxManager()
        self.wireshark = WiresharkManager()
        self.file_mgr = PcapFileManager()
        self.routing = NetworkRoutingEngine()

        self._is_alive = True

        # Proyectos / Topologías Disponibles
        self.topology_projects: list[dict] = []
        self.current_project_vms: list[str] | None = None

        # Datos de Topología Activa
        self.topology: dict = {}
        self.canvas_nodes: dict = {}
        self.canvas_links: list = []
        self.selected_node_id: str | None = None
        self.dragging_node: str | None = None
        self.drag_offset_x = 0
        self.drag_offset_y = 0

        # Animación
        self.animating_packet = False

        # Estado de Captura
        self.active_capture_file: str | None = None
        self.active_capture_vm: str = DEFAULT_VM
        self.active_capture_adapter: int = 1
        self.is_capturing: bool = False
        self.capture_start_time: float = 0.0

        # Ventana Principal
        self.title(APP_TITLE)
        self.geometry("1200x840")
        self.minsize(1020, 720)
        self.configure(bg=COLOR_BG)

        # Cargar icono oficial de VirtualShark
        ico_path = os.path.join(os.path.dirname(__file__), "assets", "icon.ico")
        if os.path.exists(ico_path):
            try:
                self.iconbitmap(ico_path)
            except Exception:
                pass

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._setup_styles()
        self._build_ui()

        # Cargar datos iniciales
        self._discover_projects_and_load_default()
        self._refresh_vm_list()
        self._refresh_file_list()
        self._start_background_loops()

    def safe_after(self, delay: int, callback):
        if not self._is_alive:
            return
        try:
            self.after(delay, callback)
        except (RuntimeError, tk.TclError):
            pass

    def _on_close(self):
        self._is_alive = False
        self.destroy()

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=COLOR_PANEL,
            foreground=COLOR_TEXT,
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLOR_CARD)],
            foreground=[("selected", "#38bdf8")],
        )

        style.configure(
            "Custom.Treeview",
            background=COLOR_PANEL,
            foreground=COLOR_TEXT,
            fieldbackground=COLOR_PANEL,
            rowheight=30,
            font=("Segoe UI", 10),
            borderwidth=0,
        )
        style.configure(
            "Custom.Treeview.Heading",
            background="#0f172a",
            foreground="#38bdf8",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padding=(8, 6),
        )
        style.map(
            "Custom.Treeview",
            background=[("selected", "#0284c7")],
            foreground=[("selected", "#ffffff")],
        )
        style.configure("TCombobox", padding=5, font=("Segoe UI", 10))

    def _build_ui(self):
        # 1. HEADER
        header = tk.Frame(self, bg="#0b1120", height=65)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        header_content = tk.Frame(header, bg="#0b1120")
        header_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=8)

        lbl_title = tk.Label(
            header_content,
            text="🦈 VirtualShark Pro",
            font=("Segoe UI", 18, "bold"),
            fg="#38bdf8",
            bg="#0b1120",
        )
        lbl_title.pack(side=tk.LEFT)

        lbl_sub = tk.Label(
            header_content,
            text="Topología Cisco Multirred & Capturas Wireshark para VirtualBox",
            font=("Segoe UI", 10),
            fg=COLOR_MUTED,
            bg="#0b1120",
        )
        lbl_sub.pack(side=tk.LEFT, padx=(15, 0), pady=(4, 0))

        ind_frame = tk.Frame(header_content, bg="#0b1120")
        ind_frame.pack(side=tk.RIGHT, pady=4)

        vb_color = "#10b981" if self.vbox.is_available() else "#ef4444"
        tk.Label(
            ind_frame,
            text="● VBoxManage",
            font=("Segoe UI", 9, "bold"),
            fg=vb_color,
            bg="#1e293b",
            padx=8,
            pady=3,
        ).pack(side=tk.LEFT, padx=3)

        ws_color = "#38bdf8" if self.wireshark.is_available() else "#f59e0b"
        tk.Label(
            ind_frame,
            text="● Wireshark",
            font=("Segoe UI", 9, "bold"),
            fg=ws_color,
            bg="#1e293b",
            padx=8,
            pady=3,
        ).pack(side=tk.LEFT, padx=3)

        # 2. NOTEBOOK
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(10, 5))

        self.tab_topology = tk.Frame(self.notebook, bg=COLOR_BG)
        self.notebook.add(self.tab_topology, text=" 🌐 Topología Cisco & Simulador de Pings ")

        self.tab_captures = tk.Frame(self.notebook, bg=COLOR_BG)
        self.notebook.add(self.tab_captures, text=" 🦈 Gestor de Capturas & Wireshark ")

        self._build_topology_tab(self.tab_topology)
        self._build_captures_tab(self.tab_captures)

        # 3. BARRA DE ESTADO
        status_bar = tk.Frame(self, bg="#0b1120", height=28)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)

        self.lbl_status = tk.Label(
            status_bar,
            text="Listo | Selecciona un proyecto para cargar su topología.",
            font=("Segoe UI", 9),
            fg=COLOR_MUTED,
            bg="#0b1120",
            anchor="w",
            padx=15,
        )
        self.lbl_status.pack(fill=tk.BOTH, expand=True)

    # ==========================================================================
    # PESTAÑA 1: TOPOLOGÍA CISCO & SELECTOR DE PROYECTOS / REDES
    # ==========================================================================
    def _build_topology_tab(self, parent):
        # BARRA DE HERRAMIENTAS SUPERIOR CON SELECTOR DE PROYECTO
        tb = tk.Frame(parent, bg=COLOR_PANEL, height=52, padx=10, pady=8)
        tb.pack(fill=tk.X, side=tk.TOP, pady=(0, 6))

        # SELECTOR DE PROYECTO / RED INDEPENDIENTE
        tk.Label(
            tb,
            text="📁 Topología / Red:",
            font=("Segoe UI", 10, "bold"),
            fg="#38bdf8",
            bg=COLOR_PANEL,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.project_cb = ttk.Combobox(tb, width=38, state="readonly")
        self.project_cb.pack(side=tk.LEFT, padx=(0, 10))
        self.project_cb.bind("<<ComboboxSelected>>", lambda e: self._on_project_changed())

        btn_rescan = tk.Button(
            tb,
            text="🔄 Re-escanear",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_CARD,
            fg=COLOR_TEXT,
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=3,
            command=self._discover_projects_and_load_default,
        )
        btn_rescan.pack(side=tk.LEFT, padx=(0, 10))

        btn_auto_layout = tk.Button(
            tb,
            text="🎯 Auto-Acomodar",
            font=("Segoe UI", 9),
            bg=COLOR_CARD,
            fg=COLOR_TEXT,
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=3,
            command=self._apply_auto_layout,
        )
        btn_auto_layout.pack(side=tk.LEFT, padx=(0, 15))

        # CONTROLES DE PING
        tk.Label(
            tb,
            text="Ping:",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL,
        ).pack(side=tk.LEFT, padx=(0, 4))

        self.ping_src_cb = ttk.Combobox(tb, width=13, state="readonly")
        self.ping_src_cb.pack(side=tk.LEFT, padx=(0, 6))

        tk.Label(
            tb,
            text="➔",
            font=("Segoe UI", 9, "bold"),
            fg="#38bdf8",
            bg=COLOR_PANEL,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.ping_dst_cb = ttk.Combobox(tb, width=13, state="readonly")
        self.ping_dst_cb.pack(side=tk.LEFT, padx=(0, 8))

        btn_send_ping = tk.Button(
            tb,
            text="✉️ Enviar Ping",
            font=("Segoe UI", 9, "bold"),
            bg="#0284c7",
            fg="#ffffff",
            activebackground="#0369a1",
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=3,
            command=self.simulate_ping_action,
        )
        btn_send_ping.pack(side=tk.LEFT, padx=(0, 6))

        btn_matrix = tk.Button(
            tb,
            text="📊 Matriz de Red",
            font=("Segoe UI", 9, "bold"),
            bg="#10b981",
            fg="#ffffff",
            activebackground="#059669",
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=3,
            command=self.open_ping_matrix_modal,
        )
        btn_matrix.pack(side=tk.LEFT)

        # CONTENEDOR DIVIDIDO (CANVAS + INSPECTOR)
        split = tk.Frame(parent, bg=COLOR_BG)
        split.pack(fill=tk.BOTH, expand=True)

        canvas_frame = tk.Frame(split, bg=COLOR_PANEL, bd=1, relief="solid")
        canvas_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(
            canvas_frame,
            bg="#0a0f1d",
            highlightthickness=0,
            cursor="arrow",
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.canvas.bind("<ButtonPress-1>", self._on_canvas_click)
        self.canvas.bind("<B1-Motion>", self._on_canvas_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_canvas_release)
        self.canvas.bind("<Configure>", lambda e: self._redraw_canvas())

        # INSPECTOR DERECHO
        right_panel = tk.Frame(split, bg=COLOR_PANEL, width=340, padx=12, pady=10)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(8, 0))
        right_panel.pack_propagate(False)

        tk.Label(
            right_panel,
            text="🔍 Inspector de Equipo / Red",
            font=("Segoe UI", 12, "bold"),
            fg="#38bdf8",
            bg=COLOR_PANEL,
        ).pack(anchor="w", pady=(0, 10))

        self.card_details = tk.Frame(right_panel, bg=COLOR_CARD, padx=10, pady=10, bd=1, relief="solid")
        self.card_details.pack(fill=tk.X, pady=(0, 10))

        self.lbl_node_name = tk.Label(
            self.card_details,
            text="Selecciona un equipo",
            font=("Segoe UI", 12, "bold"),
            fg="#ffffff",
            bg=COLOR_CARD,
        )
        self.lbl_node_name.pack(anchor="w")

        self.lbl_node_type = tk.Label(
            self.card_details,
            text="Haz clic en cualquier nodo del diagrama",
            font=("Segoe UI", 9),
            fg=COLOR_MUTED,
            bg=COLOR_CARD,
        )
        self.lbl_node_type.pack(anchor="w", pady=(2, 6))

        self.txt_node_info = tk.Text(
            self.card_details,
            height=6,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#1e293b",
            fg="#e2e8f0",
            relief="flat",
            padx=6,
            pady=6,
        )
        self.txt_node_info.pack(fill=tk.X)

        btn_box = tk.Frame(self.card_details, bg=COLOR_CARD)
        btn_box.pack(fill=tk.X, pady=(8, 0))

        self.btn_node_power = tk.Button(
            btn_box,
            text="▶ Encender VM",
            font=("Segoe UI", 8, "bold"),
            bg="#10b981",
            fg="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=3,
            command=self._toggle_selected_node_power,
        )
        self.btn_node_power.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_node_capture = tk.Button(
            btn_box,
            text="🦈 Capturar Aquí",
            font=("Segoe UI", 8, "bold"),
            bg="#0284c7",
            fg="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=3,
            command=self._start_capture_on_selected_node,
        )
        self.btn_node_capture.pack(side=tk.LEFT)

        tk.Label(
            right_panel,
            text="📋 Resultado de Conectividad",
            font=("Segoe UI", 11, "bold"),
            fg="#38bdf8",
            bg=COLOR_PANEL,
        ).pack(anchor="w", pady=(8, 4))

        self.txt_ping_result = tk.Text(
            right_panel,
            wrap=tk.WORD,
            font=("Segoe UI", 9),
            bg="#0f172a",
            fg="#f8fafc",
            relief="flat",
            padx=8,
            pady=8,
        )
        self.txt_ping_result.pack(fill=tk.BOTH, expand=True)

        self.txt_ping_result.insert(
            "1.0",
            "Usa el menú superior para cambiar entre tus redes independientes (ej. Red LAN A/B, Ubuntu Server, etc.). "
            "El mapa se adaptará automáticamente a la práctica seleccionada."
        )

    # ==========================================================================
    # PESTAÑA 2: GESTOR DE CAPTURAS .PCAP & WIRESHARK
    # ==========================================================================
    def _build_captures_tab(self, parent):
        card = tk.LabelFrame(
            parent,
            text=" Control de Captura de Red en VirtualBox ",
            font=("Segoe UI", 11, "bold"),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL,
            bd=1,
            relief="solid",
            padx=15,
            pady=10,
        )
        card.pack(fill=tk.X, side=tk.TOP, pady=(0, 10))

        top_row = tk.Frame(card, bg=COLOR_PANEL)
        top_row.pack(fill=tk.X)

        tk.Label(
            top_row,
            text="Máquina Virtual:",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_PANEL,
            fg=COLOR_TEXT,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.vm_combobox = ttk.Combobox(top_row, width=20, state="readonly")
        self.vm_combobox.pack(side=tk.LEFT, padx=(0, 12))
        self.vm_combobox.bind("<<ComboboxSelected>>", lambda e: self._on_vm_selected())

        self.vm_status_badge = tk.Label(
            top_row,
            text="● Verificando...",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_CARD,
            fg=COLOR_MUTED,
            padx=8,
            pady=3,
        )
        self.vm_status_badge.pack(side=tk.LEFT, padx=(0, 15))

        tk.Label(
            top_row,
            text="Adaptador:",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_PANEL,
            fg=COLOR_TEXT,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.adapter_combobox = ttk.Combobox(
            top_row,
            values=[
                "Adaptador 1 (Red Principal)",
                "Adaptador 2",
                "Adaptador 3",
                "Adaptador 4",
            ],
            width=28,
            state="readonly",
        )
        self.adapter_combobox.current(0)
        self.adapter_combobox.pack(side=tk.LEFT, padx=(0, 15))

        self.autostart_var = tk.BooleanVar(value=True)
        chk_autostart = tk.Checkbutton(
            top_row,
            text="Iniciar VM si está apagada",
            variable=self.autostart_var,
            font=("Segoe UI", 9),
            bg=COLOR_PANEL,
            fg=COLOR_TEXT,
            selectcolor="#0f172a",
            activebackground=COLOR_PANEL,
        )
        chk_autostart.pack(side=tk.LEFT)

        btn_row = tk.Frame(card, bg=COLOR_PANEL)
        btn_row.pack(fill=tk.X, pady=(10, 0))

        self.btn_start = tk.Button(
            btn_row,
            text="▶  INICIAR CAPTURA",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_SUCCESS,
            fg="#ffffff",
            activebackground="#15803d",
            relief="flat",
            cursor="hand2",
            padx=18,
            pady=6,
            command=self.start_capture_action,
        )
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_stop = tk.Button(
            btn_row,
            text="⏹  FINALIZAR CAPTURA",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_DANGER,
            fg="#ffffff",
            activebackground="#b91c1c",
            relief="flat",
            cursor="hand2",
            state=tk.DISABLED,
            padx=18,
            pady=6,
            command=self.stop_capture_action,
        )
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 15))

        self.capture_status_panel = tk.Frame(btn_row, bg=COLOR_CARD, padx=12, pady=6)
        self.capture_status_panel.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.lbl_capture_state = tk.Label(
            self.capture_status_panel,
            text="⚪ Captura Inactiva. Pulsa 'Iniciar Captura' para comenzar.",
            font=("Segoe UI", 10),
            fg=COLOR_MUTED,
            bg=COLOR_CARD,
            anchor="w",
        )
        self.lbl_capture_state.pack(fill=tk.X)

        card_files = tk.LabelFrame(
            parent,
            text=" Capturas Guardadas (.pcap) en Documentos ",
            font=("Segoe UI", 11, "bold"),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL,
            bd=1,
            relief="solid",
            padx=12,
            pady=8,
        )
        card_files.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        toolbar = tk.Frame(card_files, bg=COLOR_PANEL)
        toolbar.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            toolbar,
            text=f"Carpeta: {self.file_mgr.directory}",
            font=("Segoe UI", 9),
            fg=COLOR_MUTED,
            bg=COLOR_PANEL,
        ).pack(side=tk.LEFT)

        btn_open_dir = tk.Button(
            toolbar,
            text="📂 Abrir Carpeta",
            font=("Segoe UI", 8),
            bg=COLOR_CARD,
            fg=COLOR_TEXT,
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=2,
            command=self._open_documents_folder,
        )
        btn_open_dir.pack(side=tk.RIGHT, padx=(6, 0))

        btn_ref = tk.Button(
            toolbar,
            text="🔄 Actualizar",
            font=("Segoe UI", 8),
            bg=COLOR_CARD,
            fg=COLOR_TEXT,
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=2,
            command=self._refresh_file_list,
        )
        btn_ref.pack(side=tk.RIGHT)

        tree_box = tk.Frame(card_files, bg=COLOR_PANEL)
        tree_box.pack(fill=tk.BOTH, expand=True)

        cols = ("name", "datetime", "size", "status")
        self.tree = ttk.Treeview(
            tree_box,
            columns=cols,
            show="headings",
            style="Custom.Treeview",
            selectmode="browse",
        )
        self.tree.heading("name", text="Nombre del Archivo .pcap", anchor="w")
        self.tree.heading("datetime", text="Fecha y Hora Exacta", anchor="w")
        self.tree.heading("size", text="Tamaño", anchor="e")
        self.tree.heading("status", text="Estado", anchor="center")

        self.tree.column("name", width=380, anchor="w")
        self.tree.column("datetime", width=180, anchor="w")
        self.tree.column("size", width=110, anchor="e")
        self.tree.column("status", width=110, anchor="center")

        vsb = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.tag_configure("even", background="#1e293b")
        self.tree.tag_configure("odd", background="#0f172a")
        self.tree.tag_configure("recording", background="#450a0a", foreground="#f87171")

        self.tree.bind("<Double-1>", lambda e: self.open_with_wireshark_action())

        action_bar = tk.Frame(card_files, bg=COLOR_PANEL)
        action_bar.pack(fill=tk.X, pady=(8, 0))

        btn_ws = tk.Button(
            action_bar,
            text="🦈  ABRIR CON WIRESHARK",
            font=("Segoe UI", 10, "bold"),
            bg="#0284c7",
            fg="#ffffff",
            activebackground="#0369a1",
            relief="flat",
            cursor="hand2",
            padx=16,
            pady=6,
            command=self.open_with_wireshark_action,
        )
        btn_ws.pack(side=tk.LEFT, padx=(0, 10))

        btn_del = tk.Button(
            action_bar,
            text="🗑️  ELIMINAR",
            font=("Segoe UI", 10, "bold"),
            bg="#ef4444",
            fg="#ffffff",
            activebackground="#dc2626",
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=6,
            command=self.delete_file_action,
        )
        btn_del.pack(side=tk.LEFT)

        self.lbl_stats = tk.Label(
            action_bar,
            text="0 capturas | 0 KB",
            font=("Segoe UI", 9),
            fg=COLOR_MUTED,
            bg=COLOR_PANEL,
        )
        self.lbl_stats.pack(side=tk.RIGHT)

        log_box = tk.LabelFrame(
            parent,
            text=" Registro de Comandos y Eventos ",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL,
            bd=1,
            relief="solid",
            padx=8,
            pady=4,
        )
        log_box.pack(fill=tk.X, side=tk.BOTTOM)

        self.log_text = tk.Text(
            log_box,
            height=3,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#0b1120",
            fg="#e2e8f0",
            relief="flat",
            padx=6,
            pady=4,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_text.tag_configure("INFO", foreground="#38bdf8")
        self.log_text.tag_configure("SUCCESS", foreground="#34d399")
        self.log_text.tag_configure("WARNING", foreground="#fbbf24")
        self.log_text.tag_configure("ERROR", foreground="#f87171")

    # ==========================================================================
    # LOGGING
    # ==========================================================================
    def log(self, message: str, level: str = "INFO"):
        now = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{now}] ", "TIME")
        self.log_text.insert(tk.END, f"[{level}] ", level)
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.lbl_status.config(text=f"[{now}] {message}")

    # ==========================================================================
    # DETECCIÓN Y CAMBIO DE PROYECTOS / TOPOLOGÍAS INDEPENDIENTES
    # ==========================================================================
    def _discover_projects_and_load_default(self):
        def task():
            projects = self.vbox.detect_topology_projects()
            self.safe_after(0, lambda: self._on_projects_discovered(projects))

        threading.Thread(target=task, daemon=True).start()

    def _on_projects_discovered(self, projects: list[dict]):
        self.topology_projects = projects

        options = []
        for p in projects:
            options.append(p["title"])

        options.append("🌐 Ver Todas las Máquinas y Redes (Global)")
        options.append("⚙️ Selección Personalizada (Elegir máquinas)...")

        self.project_cb["values"] = options

        if options:
            self.project_cb.current(0)
            self._load_project_by_index(0)

    def _on_project_changed(self):
        idx = self.project_cb.current()
        num_presets = len(self.topology_projects)

        if idx < num_presets:
            self._load_project_by_index(idx)
        elif idx == num_presets:
            # Ver Todas
            all_vms = self.vbox.list_vms()
            self._load_topology_for_vms(all_vms, "Todas las Redes")
        elif idx == num_presets + 1:
            # Selección personalizada
            self._open_custom_selection_dialog()

    def _load_project_by_index(self, idx: int):
        proj = self.topology_projects[idx]
        self._load_topology_for_vms(proj["vms"], proj["title"])

    def _open_custom_selection_dialog(self):
        all_vms = self.vbox.list_vms()
        if not all_vms:
            return

        dialog = tk.Toplevel(self)
        dialog.title("Selección Personalizada de Máquinas")
        dialog.geometry("450x420")
        dialog.configure(bg=COLOR_BG)

        tk.Label(
            dialog,
            text="Selecciona qué máquinas incluir en el mapa:",
            font=("Segoe UI", 11, "bold"),
            fg="#38bdf8",
            bg=COLOR_BG,
        ).pack(pady=(12, 8))

        frame = tk.Frame(dialog, bg=COLOR_PANEL, padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        vars_dict = {}
        for vm in all_vms:
            v = tk.BooleanVar(value=(self.current_project_vms and vm in self.current_project_vms))
            chk = tk.Checkbutton(
                frame,
                text=vm,
                variable=v,
                font=("Segoe UI", 10),
                bg=COLOR_PANEL,
                fg=COLOR_TEXT,
                selectcolor="#0f172a",
                activebackground=COLOR_PANEL,
                anchor="w",
            )
            chk.pack(fill=tk.X, pady=2)
            vars_dict[vm] = v

        btn_row = tk.Frame(dialog, bg=COLOR_BG, pady=10)
        btn_row.pack(fill=tk.X, padx=15)

        def apply_selection():
            selected = [vm for vm, var in vars_dict.items() if var.get()]
            if not selected:
                messagebox.showwarning("Atención", "Debes seleccionar al menos una máquina.")
                return
            dialog.destroy()
            self._load_topology_for_vms(selected, f"Personalizada ({len(selected)} VMs)")

        tk.Button(
            btn_row,
            text="✔ Cargar Topología",
            font=("Segoe UI", 10, "bold"),
            bg="#10b981",
            fg="#ffffff",
            relief="flat",
            padx=12,
            pady=4,
            command=apply_selection,
        ).pack(side=tk.RIGHT)

        tk.Button(
            btn_row,
            text="Cancelar",
            font=("Segoe UI", 9),
            bg=COLOR_CARD,
            fg=COLOR_TEXT,
            relief="flat",
            padx=10,
            pady=4,
            command=dialog.destroy,
        ).pack(side=tk.RIGHT, padx=6)

    def _load_topology_for_vms(self, vms: list[str], title: str = ""):
        self.current_project_vms = vms
        self.log(f"Cargando topología para: {title or ', '.join(vms)}...", "INFO")

        def task():
            topo = self.vbox.scan_full_topology(filter_vms=vms)
            self.safe_after(0, lambda: self._on_topology_scanned(topo))

        threading.Thread(target=task, daemon=True).start()

    def _on_topology_scanned(self, topo: dict):
        self.topology = topo
        vm_names = list(topo["vms"].keys())

        # Actualizar combos de ping
        self.ping_src_cb["values"] = vm_names
        self.ping_dst_cb["values"] = vm_names

        if vm_names:
            self.ping_src_cb.current(0)
            if len(vm_names) > 1:
                self.ping_dst_cb.current(1)
            else:
                self.ping_dst_cb.current(0)

        # Aplicar layout centrado y limpio para esta topología
        self._apply_auto_layout()
        self.log(f"Topología lista: {len(vm_names)} equipos, {len(topo['switches'])} switches.", "SUCCESS")

    # ==========================================================================
    # DIBUJO Y AUTO-LAYOUT INTELIGENTE
    # ==========================================================================
    def _apply_auto_layout(self):
        w = max(self.canvas.winfo_width(), 780)
        h = max(self.canvas.winfo_height(), 560)

        vms = self.topology.get("vms", {})
        switches = self.topology.get("switches", {})
        nat = self.topology.get("nat_clouds", {})

        self.canvas_nodes = {}

        sw_keys = list(switches.keys())
        num_switches = len(sw_keys)

        # 1. Si hay Routers
        routers = [v for v, d in vms.items() if d["type"] == "router" or "router" in v.lower()]
        non_routers = [v for v in vms.keys() if v not in routers]

        # Posicionar Routers en la parte superior o central
        for idx, r in enumerate(routers):
            rx = w * (0.5 if len(routers) == 1 else (0.3 + idx * 0.4))
            ry = h * 0.32
            self.canvas_nodes[r] = {
                "type": "router",
                "name": r,
                "x": rx,
                "y": ry,
                "color": COLOR_ROUTER,
                "icon": "🔀"
            }

        # 2. Posicionar Switches Virtuales
        sw_positions = {}
        if num_switches == 1:
            sw_positions[sw_keys[0]] = (w * 0.5, h * (0.55 if routers else 0.45))
        elif num_switches == 2:
            sw_positions[sw_keys[0]] = (w * 0.30, h * 0.55)
            sw_positions[sw_keys[1]] = (w * 0.70, h * 0.55)
        else:
            for idx, sw in enumerate(sw_keys):
                frac = (idx + 1) / (num_switches + 1)
                sw_positions[sw] = (w * frac, h * 0.55)

        for sw_key, pos in sw_positions.items():
            sw_data = switches[sw_key]
            self.canvas_nodes[f"SWITCH:{sw_key}"] = {
                "type": "switch",
                "name": sw_data["name"],
                "key": sw_key,
                "x": pos[0],
                "y": pos[1],
                "color": COLOR_SWITCH,
                "icon": "🔀"
            }

        # 3. Posicionar Clientes y Servidores alrededor de sus switches
        # Agrupar máquinas por el switch al que conectan principalmente
        sw_members = defaultdict(list)
        unconnected_pcs = []

        for pc in non_routers:
            pc_sws = []
            for ad in vms[pc]["adapters"].values():
                if ad["mode"] in ("intnet", "hostonly"):
                    pc_sws.append(f"{ad['mode'].upper()}:{ad['net_name']}")

            if pc_sws:
                sw_members[pc_sws[0]].append(pc)
            else:
                unconnected_pcs.append(pc)

        # Distribuir equipos de cada switch en abanico
        for sw_key, members in sw_members.items():
            if sw_key not in sw_positions:
                continue
            sw_x, sw_y = sw_positions[sw_key]
            total_m = len(members)

            # Si es el switch de la izquierda, poner PCs más a la izquierda
            is_left = (sw_x < w * 0.45)
            is_right = (sw_x > w * 0.55)

            for m_idx, pc in enumerate(members):
                device_type = vms[pc]["type"]
                icon = "🖥️" if device_type == "pc" else "🖥️"
                color = COLOR_PC if device_type == "pc" else COLOR_SERVER

                if is_left:
                    offset_x = -130
                    offset_y = (m_idx - (total_m - 1) / 2) * 85
                elif is_right:
                    offset_x = 130
                    offset_y = (m_idx - (total_m - 1) / 2) * 85
                else:
                    offset_x = (m_idx - (total_m - 1) / 2) * 120
                    offset_y = 120

                px = max(min(sw_x + offset_x, w - 80), 80)
                py = max(min(sw_y + offset_y, h - 80), 80)

                self.canvas_nodes[pc] = {
                    "type": device_type,
                    "name": pc,
                    "x": px,
                    "y": py,
                    "color": color,
                    "icon": icon
                }

        # Máquinas sin switch (NAT solo)
        for idx, pc in enumerate(unconnected_pcs):
            self.canvas_nodes[pc] = {
                "type": vms[pc]["type"],
                "name": pc,
                "x": w * 0.2 + idx * 110,
                "y": h * 0.85,
                "color": COLOR_PC,
                "icon": "🖥️"
            }

        # 4. Nube NAT
        if nat:
            self.canvas_nodes["CLOUD:NAT"] = {
                "type": "cloud",
                "name": "Internet / NAT",
                "x": w * 0.84,
                "y": h * 0.16,
                "color": COLOR_CLOUD,
                "icon": "☁️"
            }

        self._redraw_canvas()

    def _sync_node_states(self):
        vms = self.topology.get("vms", {})
        for node_id, data in self.canvas_nodes.items():
            if data["type"] in ("pc", "router", "server") and node_id in vms:
                data["state"] = vms[node_id]["state"]

    def _redraw_canvas(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()

        grid_size = 35
        for x in range(0, w, grid_size):
            self.canvas.create_line(x, 0, x, h, fill="#131b2e", width=1)
        for y in range(0, h, grid_size):
            self.canvas.create_line(0, y, w, y, fill="#131b2e", width=1)

        self.canvas_links = []
        vms = self.topology.get("vms", {})

        # Dibujar Enlaces (Cables)
        for vm_name, vm_data in vms.items():
            if vm_name not in self.canvas_nodes:
                continue
            src_node = self.canvas_nodes[vm_name]

            for ad_idx, ad in vm_data["adapters"].items():
                mode = ad["mode"]
                net_name = ad["net_name"]

                target_node_id = None
                if mode in ("intnet", "hostonly"):
                    target_node_id = f"SWITCH:{mode.upper()}:{net_name}"
                elif mode == "nat" and "CLOUD:NAT" in self.canvas_nodes:
                    target_node_id = "CLOUD:NAT"

                if target_node_id and target_node_id in self.canvas_nodes:
                    dst_node = self.canvas_nodes[target_node_id]
                    link_tuple = (vm_name, target_node_id, ad_idx, ad["mac"])
                    self.canvas_links.append(link_tuple)

                    is_running = (vm_data["state"] == "running")
                    line_color = COLOR_CABLE_ACTIVE if is_running else COLOR_CABLE
                    line_dash = () if is_running else (4, 4)
                    line_width = 3 if is_running else 2

                    self.canvas.create_line(
                        src_node["x"], src_node["y"],
                        dst_node["x"], dst_node["y"],
                        fill=line_color,
                        width=line_width,
                        dash=line_dash,
                        tags=("link", f"link_{vm_name}", f"link_{target_node_id}")
                    )

                    dx = dst_node["x"] - src_node["x"]
                    dy = dst_node["y"] - src_node["y"]
                    dist = math.hypot(dx, dy)
                    if dist > 40:
                        px = src_node["x"] + (dx / dist) * 35
                        py = src_node["y"] + (dy / dist) * 35
                        led_color = "#22c55e" if is_running else "#ef4444"
                        self.canvas.create_oval(px - 4, py - 4, px + 4, py + 4, fill=led_color, outline="#ffffff")
                        self.canvas.create_text(px + 12, py, text=f"nic{ad_idx}", fill=COLOR_MUTED, font=("Segoe UI", 8))

        # Dibujar Nodos Cisco
        for node_id, node in self.canvas_nodes.items():
            x, y = node["x"], node["y"]
            ntype = node["type"]
            is_selected = (self.selected_node_id == node_id)

            if is_selected:
                self.canvas.create_oval(x - 38, y - 38, x + 38, y + 38, outline="#38bdf8", width=3, dash=(4, 2))

            if ntype == "router":
                self.canvas.create_oval(x - 30, y - 30, x + 30, y + 30, fill=COLOR_ROUTER, outline="#38bdf8", width=2, tags=("node", node_id))
                self.canvas.create_text(x, y - 4, text="🔀", font=("Segoe UI", 16), fill="#ffffff", tags=("node", node_id))
                self.canvas.create_text(x, y + 14, text="ROUTER", font=("Segoe UI", 7, "bold"), fill="#ffffff", tags=("node", node_id))

            elif ntype == "switch":
                self.canvas.create_rectangle(x - 44, y - 22, x + 44, y + 22, fill=COLOR_SWITCH, outline="#34d399", width=2, tags=("node", node_id))
                self.canvas.create_text(x, y - 3, text="⇄ ⇅ ⇄", font=("Segoe UI", 11, "bold"), fill="#ffffff", tags=("node", node_id))
                self.canvas.create_text(x, y + 11, text="SWITCH", font=("Segoe UI", 7, "bold"), fill="#ffffff", tags=("node", node_id))

            elif ntype in ("pc", "server"):
                border_col = "#818cf8" if ntype == "pc" else "#a78bfa"
                self.canvas.create_rectangle(x - 26, y - 24, x + 26, y + 14, fill=node["color"], outline=border_col, width=2, tags=("node", node_id))
                self.canvas.create_line(x, y + 14, x, y + 22, fill=border_col, width=3, tags=("node", node_id))
                self.canvas.create_line(x - 14, y + 22, x + 14, y + 22, fill=border_col, width=3, tags=("node", node_id))
                self.canvas.create_text(x, y - 5, text="🖥️", font=("Segoe UI", 14), tags=("node", node_id))

            elif ntype == "cloud":
                self.canvas.create_oval(x - 36, y - 20, x + 36, y + 20, fill=COLOR_CLOUD, outline="#67e8f9", width=2, tags=("node", node_id))
                self.canvas.create_text(x, y, text="☁️ Internet", font=("Segoe UI", 9, "bold"), fill="#0f172a", tags=("node", node_id))

            label_text = node["name"]
            if ntype in ("pc", "router", "server") and node_id in vms:
                state = vms[node_id]["state"]
                state_bullet = "🟢" if state == "running" else "⚪"
                label_text = f"{state_bullet} {node['name']}"

            self.canvas.create_text(
                x, y + 36,
                text=label_text,
                font=("Segoe UI", 10, "bold"),
                fill="#f8fafc",
                tags=("node", node_id)
            )

    def _on_canvas_click(self, event):
        item = self.canvas.find_closest(event.x, event.y, halo=15)
        if not item:
            return

        tags = self.canvas.gettags(item[0])
        node_id = None
        for t in tags:
            if t in self.canvas_nodes:
                node_id = t
                break

        if node_id:
            self.selected_node_id = node_id
            self.dragging_node = node_id
            self.drag_offset_x = self.canvas_nodes[node_id]["x"] - event.x
            self.drag_offset_y = self.canvas_nodes[node_id]["y"] - event.y
            self._update_inspector_card(node_id)
            self._redraw_canvas()

    def _on_canvas_drag(self, event):
        if self.dragging_node and self.dragging_node in self.canvas_nodes:
            self.canvas_nodes[self.dragging_node]["x"] = event.x + self.drag_offset_x
            self.canvas_nodes[self.dragging_node]["y"] = event.y + self.drag_offset_y
            self._redraw_canvas()

    def _on_canvas_release(self, event):
        self.dragging_node = None

    def _update_inspector_card(self, node_id: str):
        node = self.canvas_nodes.get(node_id)
        if not node:
            return

        self.lbl_node_name.config(text=f"{node['icon']} {node['name']}")
        ntype = node["type"].upper()
        self.lbl_node_type.config(text=f"Tipo: {ntype}")

        self.txt_node_info.delete("1.0", tk.END)

        vms = self.topology.get("vms", {})
        if node_id in vms:
            vm = vms[node_id]
            state = vm["state"].upper()
            self.txt_node_info.insert(tk.END, f"Estado VM: {state}\n")
            self.txt_node_info.insert(tk.END, "Adaptadores de Red:\n")
            for idx, ad in vm["adapters"].items():
                self.txt_node_info.insert(tk.END, f" • nic{idx}: {ad['mode']} [{ad['net_name']}]\n")
                self.txt_node_info.insert(tk.END, f"   MAC: {ad['mac']}\n")

            is_running = (vm["state"] == "running")
            self.btn_node_power.config(
                text="⏹ Apagar VM" if is_running else "▶ Arrancar VM",
                bg="#ef4444" if is_running else "#10b981",
                state=tk.NORMAL
            )
            self.btn_node_capture.config(state=tk.NORMAL)
        elif node["type"] == "switch":
            sw_key = node["key"]
            switches = self.topology.get("switches", {})
            sw = switches.get(sw_key, {})
            self.txt_node_info.insert(tk.END, f"Switch Virtual ({sw.get('mode', 'intnet')})\n")
            self.txt_node_info.insert(tk.END, f"Puertos Conectados: {len(sw.get('ports', []))}\n")
            for p in sw.get("ports", []):
                self.txt_node_info.insert(tk.END, f" • {p['vm']} (nic{p['adapter']})\n")

            self.btn_node_power.config(state=tk.DISABLED, text="Switch Virtual", bg=COLOR_CARD)
            self.btn_node_capture.config(state=tk.DISABLED)
        else:
            self.btn_node_power.config(state=tk.DISABLED)
            self.btn_node_capture.config(state=tk.DISABLED)

    def _toggle_selected_node_power(self):
        if not self.selected_node_id:
            return
        vms = self.topology.get("vms", {})
        if self.selected_node_id not in vms:
            return

        vm_name = self.selected_node_id
        is_running = (vms[vm_name]["state"] == "running")

        def task():
            if is_running:
                self.vbox.stop_vm(vm_name)
            else:
                self.vbox.start_vm(vm_name)
            time.sleep(1.5)
            self.safe_after(0, lambda: self._on_vm_toggled())

        threading.Thread(target=task, daemon=True).start()

    def _on_vm_toggled(self):
        if self.current_project_vms:
            self._load_topology_for_vms(self.current_project_vms)

    def _start_capture_on_selected_node(self):
        if not self.selected_node_id:
            return
        vms = self.topology.get("vms", {})
        if self.selected_node_id in vms:
            self.vm_combobox.set(self.selected_node_id)
            self.notebook.select(self.tab_captures)
            self.start_capture_action()

    # ==========================================================================
    # SIMULACIÓN DE PINGS
    # ==========================================================================
    def simulate_ping_action(self):
        src = self.ping_src_cb.get()
        dst = self.ping_dst_cb.get()

        if not src or not dst:
            messagebox.showwarning("Atención", "Selecciona una máquina de origen y una de destino.")
            return

        result = self.routing.analyze_ping(src, dst, self.topology)

        self.txt_ping_result.delete("1.0", tk.END)

        tipo = result.get("type", "UNKNOWN")
        success = result.get("success", False)

        if success:
            self.txt_ping_result.insert(tk.END, f"✔ PING EXITOSO ({tipo})\n")
        else:
            self.txt_ping_result.insert(tk.END, f"✖ PING FALLIDO ({tipo})\n")

        self.txt_ping_result.insert(tk.END, f"\n{result['message']}\n\n")

        if "hops" in result:
            self.txt_ping_result.insert(tk.END, "Ruta y Análisis de Paquetes:\n")
            for h in result["hops"]:
                self.txt_ping_result.insert(tk.END, f"{h}\n")

        self.log(f"Ping simulado: {src} -> {dst} [{tipo}]", "INFO" if success else "WARNING")

        path_nodes = result.get("path", [])
        if len(path_nodes) >= 2:
            self._animate_packet_along_path(path_nodes, success)

    def _animate_packet_along_path(self, path_nodes: list, success: bool):
        if self.animating_packet:
            return
        self.animating_packet = True

        points = []
        for n in path_nodes:
            if n in self.canvas_nodes:
                points.append((self.canvas_nodes[n]["x"], self.canvas_nodes[n]["y"]))

        if len(points) < 2:
            self.animating_packet = False
            return

        packet_id = self.canvas.create_oval(
            points[0][0] - 8, points[0][1] - 8,
            points[0][0] + 8, points[0][1] + 8,
            fill=COLOR_PACKET, outline="#ffffff", width=2
        )

        def step_animation(segment_idx: int, t: float):
            if segment_idx >= len(points) - 1:
                self.canvas.delete(packet_id)
                self.animating_packet = False
                last_pt = points[-1]
                pulse_color = "#22c55e" if success else "#ef4444"
                pulse_id = self.canvas.create_oval(
                    last_pt[0] - 25, last_pt[1] - 25,
                    last_pt[0] + 25, last_pt[1] + 25,
                    outline=pulse_color, width=4
                )
                self.canvas.after(500, lambda: self.canvas.delete(pulse_id))
                return

            p_start = points[segment_idx]
            p_end = points[segment_idx + 1]

            cur_x = p_start[0] + (p_end[0] - p_start[0]) * t
            cur_y = p_start[1] + (p_end[1] - p_start[1]) * t

            self.canvas.coords(packet_id, cur_x - 8, cur_y - 8, cur_x + 8, cur_y + 8)

            new_t = t + 0.12
            if new_t >= 1.0:
                self.safe_after(25, lambda: step_animation(segment_idx + 1, 0.0))
            else:
                self.safe_after(25, lambda: step_animation(segment_idx, new_t))

        step_animation(0, 0.0)

    def open_ping_matrix_modal(self):
        vms = list(self.topology.get("vms", {}).keys())
        if not vms:
            messagebox.showinfo("Información", "No hay máquinas en la topología activa.")
            return

        modal = tk.Toplevel(self)
        modal.title("Matriz de Conectividad de Red Activa")
        modal.geometry("740x480")
        modal.configure(bg=COLOR_BG)

        tk.Label(
            modal,
            text="📊 Matriz de Conectividad (Topología Activa)",
            font=("Segoe UI", 12, "bold"),
            fg="#38bdf8",
            bg=COLOR_BG,
        ).pack(pady=10)

        frame = tk.Frame(modal, bg=COLOR_PANEL, padx=12, pady=12)
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        tk.Label(frame, text="Origen \\ Destino", font=("Segoe UI", 9, "bold"), fg=COLOR_TEXT, bg=COLOR_PANEL, width=14, relief="ridge").grid(row=0, column=0, padx=2, pady=2)

        for col_idx, dst_vm in enumerate(vms, start=1):
            tk.Label(frame, text=dst_vm, font=("Segoe UI", 9, "bold"), fg="#38bdf8", bg=COLOR_PANEL, width=13, relief="ridge").grid(row=0, column=col_idx, padx=2, pady=2)

        for row_idx, src_vm in enumerate(vms, start=1):
            tk.Label(frame, text=src_vm, font=("Segoe UI", 9, "bold"), fg="#38bdf8", bg=COLOR_PANEL, width=14, relief="ridge").grid(row=row_idx, column=0, padx=2, pady=2)

            for col_idx, dst_vm in enumerate(vms, start=1):
                res = self.routing.analyze_ping(src_vm, dst_vm, self.topology)
                ptype = res.get("type")

                if ptype == "LOOPBACK":
                    cell_text = "🔄 Loopback"
                    cell_bg = "#1e293b"
                    cell_fg = "#94a3b8"
                elif ptype == "L2_DIRECT":
                    cell_text = f"🟢 L2 ({res.get('switch')})"
                    cell_bg = "#064e3b"
                    cell_fg = "#34d399"
                elif ptype == "L3_ROUTED":
                    cell_text = f"🟡 L3 ({res.get('router')})"
                    cell_bg = "#78350f"
                    cell_fg = "#fbbf24"
                else:
                    cell_text = "🔴 Sin ruta"
                    cell_bg = "#450a0a"
                    cell_fg = "#f87171"

                tk.Label(
                    frame,
                    text=cell_text,
                    font=("Segoe UI", 8, "bold"),
                    fg=cell_fg,
                    bg=cell_bg,
                    width=13,
                    relief="groove"
                ).grid(row=row_idx, column=col_idx, padx=2, pady=2)

    # ==========================================================================
    # GESTOR DE CAPTURAS
    # ==========================================================================
    def _refresh_vm_list(self):
        vms = self.vbox.list_vms()
        if not vms:
            vms = [DEFAULT_VM]

        self.vm_combobox["values"] = vms
        if DEFAULT_VM in vms:
            self.vm_combobox.set(DEFAULT_VM)
        else:
            self.vm_combobox.current(0)

        self._update_vm_status_display()

    def _on_vm_selected(self):
        self._update_vm_status_display()

    def _update_vm_status_display(self):
        vm_name = self.vm_combobox.get()
        if not vm_name:
            return

        def task():
            info = self.vbox.get_vm_state(vm_name)
            state = info["state"]
            self.safe_after(0, lambda: self._apply_vm_status_ui(state))

        threading.Thread(target=task, daemon=True).start()

    def _apply_vm_status_ui(self, state: str):
        if state == "running":
            self.vm_status_badge.config(text="● EN EJECUCIÓN (Running)", bg="#064e3b", fg="#34d399")
        elif state == "poweroff":
            self.vm_status_badge.config(text="● APAGADA (Poweroff)", bg=COLOR_CARD, fg=COLOR_MUTED)
        else:
            self.vm_status_badge.config(text=f"● {state.upper()}", bg=COLOR_CARD, fg=COLOR_WARNING)

    def _get_selected_adapter_index(self) -> int:
        idx = self.adapter_combobox.current()
        return idx + 1 if idx >= 0 else 1

    def start_capture_action(self):
        if self.is_capturing:
            messagebox.showinfo("Captura activa", "Ya existe una captura activa.")
            return

        vm_name = self.vm_combobox.get() or DEFAULT_VM
        adapter_idx = self._get_selected_adapter_index()
        pcap_path = self.file_mgr.generate_filename(vm_name=vm_name)
        filename = os.path.basename(pcap_path)

        self.log(f"Iniciando captura en {vm_name} (Adaptador {adapter_idx})...", "INFO")

        is_running = self.vbox.is_vm_running(vm_name)
        must_autostart = self.autostart_var.get()

        def task():
            if not is_running and must_autostart:
                ok, msg = self.vbox.start_nic_trace(vm_name, pcap_path, adapter_idx)
                if not ok:
                    self.safe_after(0, lambda: messagebox.showerror("Error", msg))
                    return
                self.vbox.start_vm(vm_name)
            else:
                ok, msg = self.vbox.start_nic_trace(vm_name, pcap_path, adapter_idx)
                if not ok:
                    self.safe_after(0, lambda: messagebox.showerror("Error", msg))
                    return

            self.safe_after(0, lambda: self._on_start_success(vm_name, adapter_idx, pcap_path))

        threading.Thread(target=task, daemon=True).start()

    def _on_start_success(self, vm_name: str, adapter_idx: int, pcap_path: str):
        self.is_capturing = True
        self.active_capture_file = pcap_path
        self.active_capture_vm = vm_name
        self.active_capture_adapter = adapter_idx
        self.capture_start_time = time.time()

        filename = os.path.basename(pcap_path)
        self.btn_start.config(state=tk.DISABLED, bg="#475569")
        self.btn_stop.config(state=tk.NORMAL, bg=COLOR_DANGER)
        self.capture_status_panel.config(bg="#450a0a")
        self.lbl_capture_state.config(
            text=f"🔴 GRABANDO: {filename} (Adaptador {adapter_idx}) - 00:00:00",
            fg="#f87171",
            bg="#450a0a",
            font=("Segoe UI", 10, "bold")
        )
        self.log(f"Captura iniciada: {filename}", "SUCCESS")
        self._refresh_file_list()

    def stop_capture_action(self):
        if not self.is_capturing:
            return

        vm_name = self.active_capture_vm
        adapter_idx = self.active_capture_adapter
        pcap_file = self.active_capture_file

        def task():
            ok, msg = self.vbox.stop_nic_trace(vm_name, adapter_idx)
            self.safe_after(0, lambda: self._on_stop_completed(ok, msg, pcap_file))

        threading.Thread(target=task, daemon=True).start()

    def _on_stop_completed(self, ok: bool, msg: str, pcap_file: str | None):
        self.is_capturing = False
        duration_sec = int(time.time() - self.capture_start_time) if self.capture_start_time > 0 else 0
        m, s = divmod(duration_sec, 60)
        h, m = divmod(m, 60)
        t_str = f"{h:02d}:{m:02d}:{s:02d}"

        self.btn_start.config(state=tk.NORMAL, bg=COLOR_SUCCESS)
        self.btn_stop.config(state=tk.DISABLED, bg="#475569")
        self.capture_status_panel.config(bg=COLOR_CARD)

        fn = os.path.basename(pcap_file) if pcap_file else "archivo"
        self.lbl_capture_state.config(
            text=f"✔ Captura completada: {fn} (Duración: {t_str})",
            fg="#34d399",
            bg=COLOR_CARD,
            font=("Segoe UI", 10)
        )
        self.log(f"Captura guardada: {fn} [{t_str}]", "SUCCESS")
        self.active_capture_file = None
        self._refresh_file_list()

    def _refresh_file_list(self):
        files = self.file_mgr.scan_files()
        for item in self.tree.get_children():
            self.tree.delete(item)

        total_bytes = 0
        for idx, f in enumerate(files):
            total_bytes += f["size_bytes"]
            is_active = (self.is_capturing and self.active_capture_file and os.path.abspath(f["path"]) == os.path.abspath(self.active_capture_file))
            status_str = "🔴 Grabando..." if is_active else "Completado"
            tag = "recording" if is_active else ("even" if idx % 2 == 0 else "odd")

            self.tree.insert(
                "",
                tk.END,
                iid=f["path"],
                values=(f["name"], f["datetime_fmt"], f["size_fmt"], status_str),
                tags=(tag,)
            )

        self.lbl_stats.config(text=f"Total: {len(files)} archivo(s) | {self.file_mgr._format_size(total_bytes)}")

    def open_with_wireshark_action(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona un archivo .pcap de la lista.")
            return

        filepath = selected[0]
        self.log(f"Abriendo {os.path.basename(filepath)} con Wireshark...", "INFO")
        ok, msg = self.wireshark.open_pcap(filepath)
        if ok:
            self.log(msg, "SUCCESS")
        else:
            self.log(msg, "ERROR")

    def delete_file_action(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona un archivo .pcap para eliminar.")
            return

        filepath = selected[0]
        fn = os.path.basename(filepath)

        if not messagebox.askyesno("Eliminar", f"¿Deseas eliminar permanentemente '{fn}'?"):
            return

        ok, msg = self.file_mgr.delete_file(filepath)
        if ok:
            self.log(msg, "SUCCESS")
            self._refresh_file_list()
        else:
            self.log(msg, "ERROR")

    def _open_documents_folder(self):
        try:
            os.startfile(self.file_mgr.directory)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ==========================================================================
    # BACKGROUND LOOPS
    # ==========================================================================
    def _start_background_loops(self):
        def loop_timer():
            if self.is_capturing and self.active_capture_file:
                duration_sec = int(time.time() - self.capture_start_time)
                m, s = divmod(duration_sec, 60)
                h, m = divmod(m, 60)
                fn = os.path.basename(self.active_capture_file)
                self.lbl_capture_state.config(
                    text=f"🔴 GRABANDO: {fn} (Adaptador {self.active_capture_adapter}) - {h:02d}:{m:02d}:{s:02d}"
                )
            self.safe_after(1000, loop_timer)

        def loop_vm_status():
            self._update_vm_status_display()
            self._sync_node_states()
            self.safe_after(5000, loop_vm_status)

        loop_timer()
        loop_vm_status()


# ==============================================================================
# ENTRADA
# ==============================================================================
def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    app = VirtualSharkProApp()
    app.mainloop()


if __name__ == "__main__":
    main()
