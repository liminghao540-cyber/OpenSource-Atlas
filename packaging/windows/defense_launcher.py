"""Dedicated Windows Defense GUI launcher for OpenSource Atlas V8.0.5."""
from __future__ import annotations

import json
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk

from opensource_atlas.windows_defense import (
    analyze_host_snapshot,
    collect_windows_host_snapshot,
    iter_windows_defense_events,
)
from opensource_atlas.firewall_response import (
    create_temporary_outbound_block,
    rollback_temporary_outbound_blocks,
)

APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()
DATA_DIR = APP_DIR / "data"
STATE_FILE = DATA_DIR / "firewall-response-state.json"
LEDGER_FILE = DATA_DIR / "firewall-response-ledger.jsonl"


class DefenseApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("OpenSource Atlas — Windows Defense")
        self.root.geometry("1050x720")
        self.root.minsize(820, 560)
        self.messages: queue.Queue[tuple[str, object]] = queue.Queue()
        self.stop_event = threading.Event()
        self.monitor_thread: threading.Thread | None = None
        self._build()
        self.root.after(150, self._drain_messages)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.log("就绪。监测不会自动启动；防火墙操作必须单独确认。")

    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="OpenSource Atlas · Windows Defense",
                  font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="V8.0.5 · 本机前台运行 · 默认只读 · 不上传遥测 · 不安装常驻服务",
        ).pack(anchor="w", pady=(2, 12))

        controls = ttk.LabelFrame(outer, text="主机监测（只读）", padding=10)
        controls.pack(fill="x", pady=(0, 10))
        ttk.Button(controls, text="采集一次主机快照", command=self.snapshot).pack(side="left", padx=4)
        ttk.Button(controls, text="开始限时监测（最多 5 分钟）",
                   command=self.start_monitor).pack(side="left", padx=4)
        ttk.Button(controls, text="停止监测", command=self.stop_monitor).pack(side="left", padx=4)

        response = ttk.LabelFrame(outer, text="防火墙响应（独立操作，默认不执行）", padding=10)
        response.pack(fill="x", pady=(0, 10))
        ttk.Label(response, text="目标公网 IP").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.ip_var = tk.StringVar()
        ttk.Entry(response, textvariable=self.ip_var, width=24).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Label(response, text="TTL（分钟，1–60）").grid(row=0, column=2, sticky="w", padx=4)
        self.ttl_var = tk.StringVar(value="10")
        ttk.Entry(response, textvariable=self.ttl_var, width=6).grid(row=0, column=3, sticky="w", padx=4)
        ttk.Button(response, text="预览回滚（不修改）",
                   command=self.preview_rollback).grid(row=0, column=4, padx=4)
        ttk.Button(response, text="创建临时出站阻断…",
                   command=self.create_block).grid(row=0, column=5, padx=4)
        ttk.Button(response, text="执行已归属规则回滚…",
                   command=self.rollback).grid(row=0, column=6, padx=4)
        ttk.Label(
            response,
            text="警告：阻断会影响该 IP 的全部出站连接；需要管理员权限。不要阻断网关、DNS、学校网络或你依赖的服务。",
            foreground="#a33",
        ).grid(row=1, column=0, columnspan=7, sticky="w", padx=4, pady=(6, 0))

        panel = ttk.LabelFrame(outer, text="监测结果与操作日志", padding=8)
        panel.pack(fill="both", expand=True)
        self.output = tk.Text(panel, wrap="word", height=22, font=("Consolas", 10))
        scroll = ttk.Scrollbar(panel, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.status_var = tk.StringVar(value="状态：空闲")
        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w", pady=(8, 0))

    def log(self, text: str) -> None:
        self.output.insert("end", text.rstrip() + "\n")
        self.output.see("end")

    def _worker(self, label: str, function) -> None:
        self.status_var.set(f"状态：{label}…")
        def run() -> None:
            try:
                result = function()
                self.messages.put(("result", (label, result)))
            except Exception as exc:
                self.messages.put(("error", (label, f"{type(exc).__name__}: {exc}")))
        threading.Thread(target=run, daemon=True).start()

    def _drain_messages(self) -> None:
        try:
            while True:
                kind, payload = self.messages.get_nowait()
                if kind == "result":
                    label, result = payload
                    self.status_var.set("状态：空闲")
                    self.log(f"\n=== {label} ===")
                    self.log(json.dumps(result, ensure_ascii=False, indent=2, default=str))
                elif kind == "error":
                    label, error = payload
                    self.status_var.set("状态：发生错误")
                    self.log(f"\n[{label}] {error}")
                    messagebox.showerror(label, error, parent=self.root)
                elif kind == "monitor":
                    self.log(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
                elif kind == "monitor_done":
                    self.status_var.set("状态：监测已停止")
                    self.log("限时监测结束。")
        except queue.Empty:
            pass
        self.root.after(150, self._drain_messages)

    def snapshot(self) -> None:
        def collect():
            snap = collect_windows_host_snapshot(max_connections=500, max_defender_events=50)
            return {"snapshot": snap, "findings": analyze_host_snapshot(snap)}
        self._worker("主机快照（只读）", collect)

    def start_monitor(self) -> None:
        if self.monitor_thread and self.monitor_thread.is_alive():
            messagebox.showinfo("监测", "监测已经在运行。", parent=self.root)
            return
        self.stop_event.clear()
        self.status_var.set("状态：限时监测运行中")
        self.log("开始限时前台监测：最多 60 次采样 / 5 分钟；首次采样仅建立基线。")
        def run() -> None:
            try:
                for finding in iter_windows_defense_events(
                    max_polls=60, max_runtime_seconds=300, stop_event=self.stop_event
                ):
                    self.messages.put(("monitor", finding))
            except Exception as exc:
                self.messages.put(("error", ("限时监测", f"{type(exc).__name__}: {exc}")))
            finally:
                self.messages.put(("monitor_done", None))
        self.monitor_thread = threading.Thread(target=run, daemon=True)
        self.monitor_thread.start()

    def stop_monitor(self) -> None:
        self.stop_event.set()
        self.log("已请求停止监测；当前 PowerShell 采样完成后退出。")

    def preview_rollback(self) -> None:
        self._worker("回滚预览（不修改防火墙）", lambda: rollback_temporary_outbound_blocks(
            preview=True, state_path=STATE_FILE, ledger_path=LEDGER_FILE
        ))

    def create_block(self) -> None:
        address = self.ip_var.get().strip()
        try:
            ttl = int(self.ttl_var.get().strip())
            if not 1 <= ttl <= 60:
                raise ValueError
        except ValueError:
            messagebox.showerror("输入错误", "TTL 必须是 1 到 60 的整数。", parent=self.root)
            return
        warning = (
            f"即将对 {address} 创建 {ttl} 分钟的 Windows 防火墙出站阻断。\n\n"
            "该规则会阻断此 IP 的全部出站流量，可能中断正常服务。"
            "仅在确认目标 IP、影响范围和管理员权限后继续。"
        )
        if not messagebox.askyesno("高影响操作确认", warning, icon="warning", parent=self.root):
            return
        token = simpledialog.askstring(
            "明确授权", "输入大写 BLOCK 才会继续：", parent=self.root
        )
        if token != "BLOCK":
            self.log("未提供精确授权词 BLOCK；未创建防火墙规则。")
            return
        self._worker("创建临时出站阻断", lambda: create_temporary_outbound_block(
            address, approval=token, ttl_minutes=ttl,
            state_path=STATE_FILE, ledger_path=LEDGER_FILE
        ))

    def rollback(self) -> None:
        preview = rollback_temporary_outbound_blocks(
            preview=True, state_path=STATE_FILE, ledger_path=LEDGER_FILE
        )
        self.log("\n=== 回滚预览（尚未修改）===")
        self.log(json.dumps(preview, ensure_ascii=False, indent=2))
        if not preview.get("would_remove"):
            messagebox.showinfo("回滚", "没有本程序登记的待回滚规则。", parent=self.root)
            return
        if not messagebox.askyesno(
            "确认执行回滚",
            "将尝试删除预览列出的、且所有权校验完全匹配的本程序规则。继续？",
            icon="warning", parent=self.root,
        ):
            return
        self._worker("执行精确归属回滚", lambda: rollback_temporary_outbound_blocks(
            preview=False, state_path=STATE_FILE, ledger_path=LEDGER_FILE
        ))

    def close(self) -> None:
        self.stop_event.set()
        self.root.destroy()


def main() -> int:
    root = tk.Tk()
    DefenseApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
