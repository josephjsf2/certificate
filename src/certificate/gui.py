import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from certificate.csr import (
    generate_private_key,
    build_csr,
    validate_san_entries,
    decode_csr,
)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CSR 工具")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self._build_generate_tab(notebook)
        self._build_decode_tab(notebook)

    # ── Generate CSR tab ─────────────────────────────────────────

    def _build_generate_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="產生 CSR")
        pad = {"padx": 8, "pady": 4}

        # --- Subject Fields ---
        subject_frame = ttk.LabelFrame(tab, text="Subject 欄位")
        subject_frame.pack(fill="x", **pad)

        fields = [
            ("通用名稱 (CN)*", "cn"),
            ("組織 (O)", "org"),
            ("部門 (OU)", "ou"),
            ("國家代碼 (C)", "country"),
            ("州/省 (ST)", "state"),
            ("城市 (L)", "locality"),
            ("電子郵件", "email"),
        ]
        self._entries = {}
        for row, (label, key) in enumerate(fields):
            ttk.Label(subject_frame, text=label).grid(
                row=row, column=0, sticky="w", padx=4, pady=2
            )
            entry = ttk.Entry(subject_frame, width=40)
            entry.grid(row=row, column=1, padx=4, pady=2)
            self._entries[key] = entry

        self._entries["country"].insert(0, "TW")

        # --- RSA Key Settings ---
        key_frame = ttk.LabelFrame(tab, text="RSA 金鑰設定")
        key_frame.pack(fill="x", **pad)

        ttk.Label(key_frame, text="金鑰長度").grid(
            row=0, column=0, sticky="w", padx=4, pady=2
        )
        self._key_size = ttk.Combobox(
            key_frame, values=["2048", "4096"], state="readonly", width=10
        )
        self._key_size.set("2048")
        self._key_size.grid(row=0, column=1, sticky="w", padx=4, pady=2)

        # --- SAN ---
        san_frame = ttk.LabelFrame(tab, text="Subject Alternative Names (SAN)")
        san_frame.pack(fill="x", **pad)

        ttk.Label(
            san_frame,
            text="每行一個，格式: DNS:example.com 或 IP:192.168.1.1",
            foreground="gray",
        ).pack(anchor="w", padx=4)
        self._san_text = tk.Text(san_frame, height=5, width=50)
        self._san_text.pack(fill="x", padx=4, pady=4)

        # --- Generate Button ---
        ttk.Button(tab, text="產生 CSR", command=self._on_generate).pack(pady=12)

    def _on_generate(self):
        cn = self._entries["cn"].get().strip()
        if not cn:
            messagebox.showerror("錯誤", "通用名稱 (CN) 為必填欄位")
            return

        san_raw = self._san_text.get("1.0", tk.END).strip()
        san_entries = [line for line in san_raw.splitlines() if line.strip()] if san_raw else []

        san_errors = validate_san_entries(san_entries)
        if san_errors:
            messagebox.showerror("SAN 格式錯誤", "\n".join(san_errors))
            return

        file_path = filedialog.asksaveasfilename(
            title="儲存 CSR 檔案",
            defaultextension=".csr",
            filetypes=[("CSR files", "*.csr"), ("All files", "*.*")],
            initialfile=f"{cn}.csr",
        )
        if not file_path:
            return

        if file_path.endswith(".csr"):
            key_path = file_path[:-4] + ".key"
        else:
            key_path = file_path + ".key"

        try:
            key_size = int(self._key_size.get())
            private_key = generate_private_key(key_size)
            csr_pem, key_pem = build_csr(
                private_key=private_key,
                common_name=cn,
                organization=self._entries["org"].get(),
                organizational_unit=self._entries["ou"].get(),
                country=self._entries["country"].get(),
                state=self._entries["state"].get(),
                locality=self._entries["locality"].get(),
                email=self._entries["email"].get(),
                san_entries=san_entries,
            )

            with open(file_path, "wb") as f:
                f.write(csr_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)

            messagebox.showinfo(
                "成功",
                f"CSR 已儲存至:\n{file_path}\n\n私鑰已儲存至:\n{key_path}",
            )
        except Exception as e:
            messagebox.showerror("產生失敗", str(e))

    # ── Decode CSR tab ───────────────────────────────────────────

    def _build_decode_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="檢視 CSR")
        pad = {"padx": 8, "pady": 4}

        # --- Buttons ---
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", **pad)
        ttk.Button(btn_frame, text="載入 CSR 檔案", command=self._on_load_csr).pack(
            side="left", padx=(0, 4)
        )
        ttk.Button(btn_frame, text="解碼", command=self._on_decode).pack(side="left")

        # --- PEM Input ---
        pem_frame = ttk.LabelFrame(tab, text="PEM 內容（可貼上文字）")
        pem_frame.pack(fill="x", **pad)
        self._pem_input = tk.Text(pem_frame, height=8, width=60)
        self._pem_input.pack(fill="x", padx=4, pady=4)

        # --- Decode Result ---
        result_frame = ttk.LabelFrame(tab, text="解碼結果")
        result_frame.pack(fill="both", expand=True, **pad)
        self._decode_result = tk.Text(result_frame, height=14, width=60, state="disabled")
        self._decode_result.pack(fill="both", expand=True, padx=4, pady=4)

    def _on_load_csr(self):
        file_path = filedialog.askopenfilename(
            title="選擇 CSR 檔案",
            filetypes=[("CSR files", "*.csr *.pem"), ("All files", "*.*")],
        )
        if not file_path:
            return
        with open(file_path, "rb") as f:
            pem_data = f.read()
        self._pem_input.delete("1.0", tk.END)
        self._pem_input.insert("1.0", pem_data.decode("utf-8", errors="replace"))
        self._on_decode()

    def _on_decode(self):
        pem_text = self._pem_input.get("1.0", tk.END).strip()
        if not pem_text:
            messagebox.showerror("錯誤", "請先載入或貼上 CSR 的 PEM 內容")
            return

        try:
            info = decode_csr(pem_text.encode("utf-8"))
        except ValueError as e:
            messagebox.showerror("解碼失敗", str(e))
            return

        lines = []
        lines.append("Subject:")
        for label, value in info["subject"].items():
            if value:
                lines.append(f"  {label}: {value}")

        lines.append("")
        if info["san"]:
            lines.append("SAN:")
            for entry in info["san"]:
                lines.append(f"  {entry}")
        else:
            lines.append("SAN: (無)")

        lines.append("")
        pk = info["public_key"]
        lines.append(f"公鑰: {pk['algorithm']} {pk['key_size']} bits")
        lines.append(f"簽名演算法: {info['signature_algorithm']}")

        self._decode_result.configure(state="normal")
        self._decode_result.delete("1.0", tk.END)
        self._decode_result.insert("1.0", "\n".join(lines))
        self._decode_result.configure(state="disabled")
