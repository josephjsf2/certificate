import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography import x509

from certificate.csr import (
    generate_private_key,
    build_csr,
    validate_san_entries,
    decode_csr,
)
from certificate.chain import (
    parse_pem_certificates,
    validate_chain,
    build_chain,
    export_chain_pem,
)
from certificate.pfx import load_pfx
from certificate.selfsigned import build_self_signed_cert


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("憑證工具")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self._build_generate_tab(notebook)
        self._build_decode_tab(notebook)
        self._build_validate_chain_tab(notebook)
        self._build_sort_chain_tab(notebook)
        self._build_pfx_tab(notebook)
        self._build_selfsigned_tab(notebook)

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

    # ── Validate Chain tab ──────────────────────────────────────

    def _build_validate_chain_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="驗證憑證鏈")
        pad = {"padx": 8, "pady": 4}

        # --- Buttons ---
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", **pad)
        ttk.Button(
            btn_frame, text="載入憑證檔案", command=self._on_load_chain_validate
        ).pack(side="left", padx=(0, 4))
        ttk.Button(
            btn_frame, text="驗證", command=self._on_validate_chain
        ).pack(side="left")

        # --- PEM Input ---
        pem_frame = ttk.LabelFrame(tab, text="PEM 內容（可貼上或載入含多張憑證的檔案）")
        pem_frame.pack(fill="x", **pad)
        self._chain_validate_input = tk.Text(pem_frame, height=8, width=60)
        self._chain_validate_input.pack(fill="x", padx=4, pady=4)

        # --- Validation Result ---
        result_frame = ttk.LabelFrame(tab, text="驗證結果")
        result_frame.pack(fill="both", expand=True, **pad)
        self._chain_validate_result = tk.Text(
            result_frame, height=14, width=60, state="disabled"
        )
        self._chain_validate_result.pack(fill="both", expand=True, padx=4, pady=4)

    def _on_load_chain_validate(self):
        file_path = filedialog.askopenfilename(
            title="選擇憑證檔案",
            filetypes=[("Certificate files", "*.pem *.crt *.cer"), ("All files", "*.*")],
        )
        if not file_path:
            return
        with open(file_path, "rb") as f:
            pem_data = f.read()
        self._chain_validate_input.delete("1.0", tk.END)
        self._chain_validate_input.insert(
            "1.0", pem_data.decode("utf-8", errors="replace")
        )

    def _on_validate_chain(self):
        pem_text = self._chain_validate_input.get("1.0", tk.END).strip()
        if not pem_text:
            messagebox.showerror("錯誤", "請先載入或貼上憑證的 PEM 內容")
            return

        certs = parse_pem_certificates(pem_text.encode("utf-8"))
        if not certs:
            messagebox.showerror("錯誤", "未找到任何有效的 PEM 憑證")
            return

        result = validate_chain(certs)

        lines = [f"共載入 {len(certs)} 張憑證", ""]
        lines.append("═══ 憑證資訊 ═══")
        for detail in result["details"]:
            lines.append(detail)
            lines.append("")

        lines.append("═══ 驗證結果 ═══")
        if result["valid"]:
            lines.append("✓ 憑證鏈驗證通過")
        else:
            lines.append("✗ 憑證鏈驗證失敗：")
            for err in result["errors"]:
                lines.append(f"  • {err}")

        self._chain_validate_result.configure(state="normal")
        self._chain_validate_result.delete("1.0", tk.END)
        self._chain_validate_result.insert("1.0", "\n".join(lines))
        self._chain_validate_result.configure(state="disabled")

    # ── Sort Chain tab ──────────────────────────────────────────

    def _build_sort_chain_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="排序憑證鏈")
        pad = {"padx": 8, "pady": 4}

        # --- Buttons ---
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", **pad)
        ttk.Button(
            btn_frame, text="載入憑證檔案", command=self._on_load_chain_sort
        ).pack(side="left", padx=(0, 4))
        ttk.Button(
            btn_frame, text="分析並排序", command=self._on_sort_chain
        ).pack(side="left", padx=(0, 4))
        ttk.Button(
            btn_frame, text="儲存", command=self._on_save_sorted_chain
        ).pack(side="left")

        # --- PEM Input ---
        input_frame = ttk.LabelFrame(tab, text="PEM 輸入（載入含多張憑證的檔案）")
        input_frame.pack(fill="x", **pad)
        self._chain_sort_input = tk.Text(input_frame, height=8, width=60)
        self._chain_sort_input.pack(fill="x", padx=4, pady=4)

        # --- Analysis Result ---
        analysis_frame = ttk.LabelFrame(tab, text="分析結果")
        analysis_frame.pack(fill="x", **pad)
        self._chain_sort_analysis = tk.Text(
            analysis_frame, height=6, width=60, state="disabled"
        )
        self._chain_sort_analysis.pack(fill="x", padx=4, pady=4)

        # --- Sorted PEM Output ---
        output_frame = ttk.LabelFrame(tab, text="排序後 PEM")
        output_frame.pack(fill="both", expand=True, **pad)
        self._chain_sort_output = tk.Text(
            output_frame, height=8, width=60, state="disabled"
        )
        self._chain_sort_output.pack(fill="both", expand=True, padx=4, pady=4)

        self._sorted_chain_pem: bytes = b""

    def _on_load_chain_sort(self):
        file_path = filedialog.askopenfilename(
            title="選擇憑證檔案",
            filetypes=[("Certificate files", "*.pem *.crt *.cer"), ("All files", "*.*")],
        )
        if not file_path:
            return
        with open(file_path, "rb") as f:
            pem_data = f.read()
        self._chain_sort_input.delete("1.0", tk.END)
        self._chain_sort_input.insert(
            "1.0", pem_data.decode("utf-8", errors="replace")
        )

    def _on_sort_chain(self):
        pem_text = self._chain_sort_input.get("1.0", tk.END).strip()
        if not pem_text:
            messagebox.showerror("錯誤", "請先載入或貼上憑證的 PEM 內容")
            return

        certs = parse_pem_certificates(pem_text.encode("utf-8"))
        if not certs:
            messagebox.showerror("錯誤", "未找到任何有效的 PEM 憑證")
            return

        sorted_certs = build_chain(certs)
        self._sorted_chain_pem = export_chain_pem(sorted_certs)

        # 分析結果
        lines = [f"找到 {len(certs)} 張憑證，排序後 {len(sorted_certs)} 張", ""]
        lines.append("排序結果（leaf → root）：")
        for i, cert in enumerate(sorted_certs):
            subject = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            cn = subject[0].value if subject else "(no CN)"
            lines.append(f"  [{i}] {cn}")

        self._chain_sort_analysis.configure(state="normal")
        self._chain_sort_analysis.delete("1.0", tk.END)
        self._chain_sort_analysis.insert("1.0", "\n".join(lines))
        self._chain_sort_analysis.configure(state="disabled")

        # PEM 輸出
        self._chain_sort_output.configure(state="normal")
        self._chain_sort_output.delete("1.0", tk.END)
        self._chain_sort_output.insert(
            "1.0", self._sorted_chain_pem.decode("utf-8", errors="replace")
        )
        self._chain_sort_output.configure(state="disabled")

    def _on_save_sorted_chain(self):
        if not self._sorted_chain_pem:
            messagebox.showerror("錯誤", "請先執行「分析並排序」")
            return

        file_path = filedialog.asksaveasfilename(
            title="儲存排序後的憑證鏈",
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile="chain.pem",
        )
        if not file_path:
            return

        with open(file_path, "wb") as f:
            f.write(self._sorted_chain_pem)

        messagebox.showinfo("成功", f"憑證鏈已儲存至:\n{file_path}")

    # ── PFX Conversion tab ───────────────────────────────────────

    def _build_pfx_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="PFX 轉換")
        pad = {"padx": 8, "pady": 4}

        # --- PFX File ---
        file_frame = ttk.LabelFrame(tab, text="PFX 檔案")
        file_frame.pack(fill="x", **pad)

        btn_row = ttk.Frame(file_frame)
        btn_row.pack(fill="x", padx=4, pady=4)
        ttk.Button(btn_row, text="載入 PFX 檔案", command=self._on_load_pfx).pack(
            side="left", padx=(0, 8)
        )
        self._pfx_file_label = ttk.Label(btn_row, text="尚未選擇檔案")
        self._pfx_file_label.pack(side="left")

        self._pfx_data: bytes = b""

        # --- Password ---
        pw_frame = ttk.LabelFrame(tab, text="密碼")
        pw_frame.pack(fill="x", **pad)

        ttk.Label(pw_frame, text="密碼:").grid(
            row=0, column=0, sticky="w", padx=4, pady=4
        )
        self._pfx_password = ttk.Entry(pw_frame, width=40, show="*")
        self._pfx_password.grid(row=0, column=1, padx=4, pady=4)

        # --- Convert Button ---
        ttk.Button(tab, text="轉換", command=self._on_convert_pfx).pack(pady=12)

        # --- Certificate Info ---
        info_frame = ttk.LabelFrame(tab, text="憑證資訊")
        info_frame.pack(fill="both", expand=True, **pad)
        self._pfx_info = tk.Text(info_frame, height=14, width=60, state="disabled")
        self._pfx_info.pack(fill="both", expand=True, padx=4, pady=4)

    def _on_load_pfx(self):
        file_path = filedialog.askopenfilename(
            title="選擇 PFX 檔案",
            filetypes=[("PFX files", "*.pfx *.p12"), ("All files", "*.*")],
        )
        if not file_path:
            return
        with open(file_path, "rb") as f:
            self._pfx_data = f.read()
        # Show just the filename
        name = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        self._pfx_file_label.configure(text=name)

    def _on_convert_pfx(self):
        if not self._pfx_data:
            messagebox.showerror("錯誤", "請先載入 PFX 檔案")
            return

        password = self._pfx_password.get()

        try:
            result = load_pfx(self._pfx_data, password)
        except Exception as e:
            messagebox.showerror("轉換失敗", f"無法解析 PFX 檔案:\n{e}")
            return

        # Display certificate info
        lines = []
        if result["certificate_info"]:
            info = result["certificate_info"]
            lines.append("═══ 主憑證 ═══")
            lines.append(f"Subject: {info['subject']}")
            lines.append(f"Issuer:  {info['issuer']}")
            lines.append(f"有效期:  {info['not_before']} ~ {info['not_after']}")
            lines.append(f"序號:    {info['serial']}")

        if result["additional_certs_info"]:
            lines.append("")
            lines.append(f"═══ 附加憑證 ({len(result['additional_certs_info'])} 張) ═══")
            for i, info in enumerate(result["additional_certs_info"]):
                lines.append(f"[{i}] Subject: {info['subject']}")
                lines.append(f"    Issuer:  {info['issuer']}")
                lines.append(f"    有效期:  {info['not_before']} ~ {info['not_after']}")

        if result["private_key_pem"]:
            lines.append("")
            lines.append("私鑰: 已提取")
        else:
            lines.append("")
            lines.append("私鑰: 無")

        self._pfx_info.configure(state="normal")
        self._pfx_info.delete("1.0", tk.END)
        self._pfx_info.insert("1.0", "\n".join(lines))
        self._pfx_info.configure(state="disabled")

        # Ask where to save
        file_path = filedialog.asksaveasfilename(
            title="儲存憑證檔案",
            defaultextension=".crt",
            filetypes=[("Certificate files", "*.crt"), ("All files", "*.*")],
        )
        if not file_path:
            return

        if file_path.endswith(".crt"):
            key_path = file_path[:-4] + ".key"
            chain_path = file_path[:-4] + "_chain.crt"
        else:
            key_path = file_path + ".key"
            chain_path = file_path + "_chain.crt"

        saved = []
        if result["certificate_pem"]:
            with open(file_path, "wb") as f:
                f.write(result["certificate_pem"])
            saved.append(f"憑證: {file_path}")

        if result["private_key_pem"]:
            with open(key_path, "wb") as f:
                f.write(result["private_key_pem"])
            saved.append(f"私鑰: {key_path}")

        if result["additional_certs_pem"]:
            with open(chain_path, "wb") as f:
                for pem in result["additional_certs_pem"]:
                    f.write(pem)
            saved.append(f"憑證鏈: {chain_path}")

        messagebox.showinfo("成功", "已儲存:\n" + "\n".join(saved))

    # ── Self-Signed Certificate tab ──────────────────────────────

    def _build_selfsigned_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="自簽憑證")
        pad = {"padx": 8, "pady": 4}

        # --- Subject Fields ---
        subject_frame = ttk.LabelFrame(tab, text="Subject 欄位")
        subject_frame.pack(fill="x", **pad)

        fields = [
            ("通用名稱 (CN)*", "ss_cn"),
            ("組織 (O)", "ss_org"),
            ("部門 (OU)", "ss_ou"),
            ("國家代碼 (C)", "ss_country"),
            ("州/省 (ST)", "ss_state"),
            ("城市 (L)", "ss_locality"),
            ("電子郵件", "ss_email"),
        ]
        for row, (label, key) in enumerate(fields):
            ttk.Label(subject_frame, text=label).grid(
                row=row, column=0, sticky="w", padx=4, pady=2
            )
            entry = ttk.Entry(subject_frame, width=40)
            entry.grid(row=row, column=1, padx=4, pady=2)
            self._entries[key] = entry

        self._entries["ss_country"].insert(0, "TW")

        # --- Key and Cert Settings ---
        settings_frame = ttk.LabelFrame(tab, text="金鑰與憑證設定")
        settings_frame.pack(fill="x", **pad)

        ttk.Label(settings_frame, text="金鑰長度").grid(
            row=0, column=0, sticky="w", padx=4, pady=2
        )
        self._ss_key_size = ttk.Combobox(
            settings_frame, values=["2048", "4096"], state="readonly", width=10
        )
        self._ss_key_size.set("2048")
        self._ss_key_size.grid(row=0, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(settings_frame, text="有效天數").grid(
            row=0, column=2, sticky="w", padx=(16, 4), pady=2
        )
        self._ss_validity = ttk.Entry(settings_frame, width=10)
        self._ss_validity.insert(0, "365")
        self._ss_validity.grid(row=0, column=3, sticky="w", padx=4, pady=2)

        self._ss_is_ca = tk.BooleanVar()
        ttk.Checkbutton(
            settings_frame, text="CA 憑證", variable=self._ss_is_ca
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=4, pady=2)

        # --- SAN ---
        san_frame = ttk.LabelFrame(tab, text="Subject Alternative Names (SAN)")
        san_frame.pack(fill="x", **pad)

        ttk.Label(
            san_frame,
            text="每行一個，格式: DNS:example.com 或 IP:192.168.1.1",
            foreground="gray",
        ).pack(anchor="w", padx=4)
        self._ss_san_text = tk.Text(san_frame, height=4, width=50)
        self._ss_san_text.pack(fill="x", padx=4, pady=4)

        # --- Generate Button ---
        ttk.Button(
            tab, text="產生自簽憑證", command=self._on_generate_selfsigned
        ).pack(pady=12)

    def _on_generate_selfsigned(self):
        cn = self._entries["ss_cn"].get().strip()
        if not cn:
            messagebox.showerror("錯誤", "通用名稱 (CN) 為必填欄位")
            return

        # Validate validity days
        try:
            validity_days = int(self._ss_validity.get().strip())
            if validity_days <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("錯誤", "有效天數必須為正整數")
            return

        # Validate SAN
        san_raw = self._ss_san_text.get("1.0", tk.END).strip()
        san_entries = (
            [line for line in san_raw.splitlines() if line.strip()] if san_raw else []
        )
        san_errors = validate_san_entries(san_entries)
        if san_errors:
            messagebox.showerror("SAN 格式錯誤", "\n".join(san_errors))
            return

        # Save dialog
        file_path = filedialog.asksaveasfilename(
            title="儲存憑證檔案",
            defaultextension=".crt",
            filetypes=[("Certificate files", "*.crt"), ("All files", "*.*")],
            initialfile=f"{cn}.crt",
        )
        if not file_path:
            return

        if file_path.endswith(".crt"):
            key_path = file_path[:-4] + ".key"
        else:
            key_path = file_path + ".key"

        try:
            key_size = int(self._ss_key_size.get())
            private_key = generate_private_key(key_size)
            cert_pem, key_pem = build_self_signed_cert(
                private_key=private_key,
                common_name=cn,
                organization=self._entries["ss_org"].get(),
                organizational_unit=self._entries["ss_ou"].get(),
                country=self._entries["ss_country"].get(),
                state=self._entries["ss_state"].get(),
                locality=self._entries["ss_locality"].get(),
                email=self._entries["ss_email"].get(),
                san_entries=san_entries,
                validity_days=validity_days,
                is_ca=self._ss_is_ca.get(),
            )

            with open(file_path, "wb") as f:
                f.write(cert_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)

            messagebox.showinfo(
                "成功",
                f"憑證已儲存至:\n{file_path}\n\n私鑰已儲存至:\n{key_path}",
            )
        except Exception as e:
            messagebox.showerror("產生失敗", str(e))
