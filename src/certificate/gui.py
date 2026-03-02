import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from certificate.csr import generate_private_key, build_csr, validate_san_entries


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CSR 產生器")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        # --- Subject Fields ---
        subject_frame = ttk.LabelFrame(self, text="Subject 欄位")
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

        # Default country to TW
        self._entries["country"].insert(0, "TW")

        # --- RSA Key Settings ---
        key_frame = ttk.LabelFrame(self, text="RSA 金鑰設定")
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
        san_frame = ttk.LabelFrame(self, text="Subject Alternative Names (SAN)")
        san_frame.pack(fill="x", **pad)

        ttk.Label(
            san_frame,
            text="每行一個，格式: DNS:example.com 或 IP:192.168.1.1",
            foreground="gray",
        ).pack(anchor="w", padx=4)
        self._san_text = tk.Text(san_frame, height=5, width=50)
        self._san_text.pack(fill="x", padx=4, pady=4)

        # --- Generate Button ---
        ttk.Button(self, text="產生 CSR", command=self._on_generate).pack(pady=12)

    def _on_generate(self):
        cn = self._entries["cn"].get().strip()
        if not cn:
            messagebox.showerror("錯誤", "通用名稱 (CN) 為必填欄位")
            return

        # Parse SAN
        san_raw = self._san_text.get("1.0", tk.END).strip()
        san_entries = [line for line in san_raw.splitlines() if line.strip()] if san_raw else []

        # Validate SAN
        san_errors = validate_san_entries(san_entries)
        if san_errors:
            messagebox.showerror("SAN 格式錯誤", "\n".join(san_errors))
            return

        # Ask save path
        file_path = filedialog.asksaveasfilename(
            title="儲存 CSR 檔案",
            defaultextension=".csr",
            filetypes=[("CSR files", "*.csr"), ("All files", "*.*")],
            initialfile=f"{cn}.csr",
        )
        if not file_path:
            return

        # Derive key path
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
