# === gui.py ===

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter.font import Font
from assembler import parse_assembly, generate_objtxt_dynamic, parse_macros, expand_macros, load_memory_from_objtxt
import re

class AssemblerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MSP430 Assembler - Token Ayrıştırmalı")
        self.root.geometry("1400x800")
        self.pages = {}  # Sayfaları saklamak için sözlük
        self.current_page = "Sayfa 1"  # Aktif sayfa
        self.setup_ui()

    def setup_ui(self):
        self.mono_font = Font(family="Consolas", size=11)
        self.bold_font = Font(family="Consolas", size=11, weight="bold")

        # En üstte bir toolbar/frame oluştur
        topbar = ttk.Frame(self.root)
        topbar.pack(side=tk.TOP, fill=tk.X)

        memory_btn = ttk.Button(topbar, text="Sanal Bellek", command=self.open_memory_popup)
        memory_btn.pack(side=tk.RIGHT, padx=10, pady=5)

        button_frame = ttk.Frame(self.root)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Çevir (F5)", command=self.convert_code).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Temizle", command=self.clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Belleği Göster", command=self.show_memory_dump).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.root, text="ESTAB Tablosu", font=self.bold_font).pack(anchor='w')

        self.estab_tree = ttk.Treeview(
            self.root,
            columns=("section", "symbol", "address"),
            show="headings",
            height=5
        )
        self.estab_tree.heading("section", text="Section")
        self.estab_tree.heading("symbol", text="Symbol")
        self.estab_tree.heading("address", text="Address")

        self.estab_tree.column("section", width=100, anchor='w')
        self.estab_tree.column("symbol", width=120, anchor='w')
        self.estab_tree.column("address", width=100, anchor='e')

        self.estab_tree.pack(fill=tk.BOTH, expand=False, padx=5, pady=5)

        main_panel = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_panel.pack(fill=tk.BOTH, expand=True)

        left_panel = ttk.PanedWindow(main_panel, orient=tk.VERTICAL)
        main_panel.add(left_panel, weight=1)

        right_panel = ttk.PanedWindow(main_panel, orient=tk.VERTICAL)
        main_panel.add(right_panel, weight=2)

        asm_frame = ttk.Frame(left_panel)
        left_panel.add(asm_frame, weight=2)

        # Assembly başlık çerçevesi
        asm_header_frame = ttk.Frame(asm_frame)
        asm_header_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(asm_header_frame, text="Assembly Kodu", font=self.bold_font).pack(side=tk.LEFT)
        
        # Sayfa seçici combobox
        self.page_selector = ttk.Combobox(asm_header_frame, width=15)
        self.page_selector.pack(side=tk.LEFT, padx=5)
        self.page_selector.bind('<<ComboboxSelected>>', self.change_page)
        
        # + butonu
        add_page_btn = ttk.Button(asm_header_frame, text="+", width=3, command=self.add_new_page)
        add_page_btn.pack(side=tk.LEFT, padx=5)

        self.asm_text = scrolledtext.ScrolledText(
            asm_frame,
            width=80,
            height=30,
            font=self.mono_font,
            wrap=tk.NONE,
            tabs=(100, 200, 300),
            tabstyle='wordprocessor'
        )
        self.asm_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # İlk sayfayı oluştur
        self.add_new_page()

        symtab_frame = ttk.Frame(left_panel)
        left_panel.add(symtab_frame, weight=1)

        ttk.Label(symtab_frame, text="Sembol Tablosu", font=self.bold_font).pack(anchor='w')

        self.symtab_tree = ttk.Treeview(
            symtab_frame,
            columns=('symbol', 'type', 'value'),
            show='headings',
            height=10
        )

        self.symtab_tree.heading('symbol', text='Sembol')
        self.symtab_tree.heading('type', text='Tip')
        self.symtab_tree.heading('value', text='Değer')

        self.symtab_tree.column('symbol', width=150, anchor='w')
        self.symtab_tree.column('type', width=80, anchor='center')
        self.symtab_tree.column('value', width=100, anchor='e')

        sym_scroll = ttk.Scrollbar(symtab_frame, orient="vertical", command=self.symtab_tree.yview)
        self.symtab_tree.configure(yscrollcommand=sym_scroll.set)
        self.symtab_tree.pack(side="left", fill="both", expand=True)
        sym_scroll.pack(side="right", fill="y")

        ttk.Label(symtab_frame, text="NAMTAB (Makro Tanımları)", font=self.bold_font).pack(anchor='w')
        self.namtab_tree = ttk.Treeview(
            symtab_frame,
            columns=("macro", "params", "size"),
            show="headings",
            height=5
        )
        self.namtab_tree.heading("macro", text="Makro")
        self.namtab_tree.heading("params", text="Parametreler")
        self.namtab_tree.heading("size", text="Satır")
        self.namtab_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(symtab_frame, text="DEFTAB (Makro Gövdesi)", font=self.bold_font).pack(anchor='w')
        self.deftab_listbox = tk.Listbox(
            symtab_frame,
            font=self.mono_font,
            height=8,
            activestyle='none'
        )
        self.deftab_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Sağ panelde bellek gösterimi için frame (başlangıçta gizli)
        self.memory_frame = ttk.Frame(self.root)
        self.memory_output = tk.Text(self.memory_frame, height=30, width=60, font=("Courier", 10))
        self.memory_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.memory_frame.pack_forget()

        right_panel = ttk.PanedWindow(main_panel, orient=tk.VERTICAL)
        main_panel.add(right_panel, weight=2)

        machine_frame = ttk.Frame(right_panel)
        right_panel.add(machine_frame, weight=1)

        ttk.Label(machine_frame, text="Makine Kodu (Token Ayrıştırmalı)", font=self.bold_font).pack(anchor='w')

        self.machine_tree = ttk.Treeview(
            machine_frame,
            columns=('address', 'opcode', 'operands', 'binary', 'comment'),
            show='headings',
            height=25
        )

        self.machine_tree.heading('address', text='Adres')
        self.machine_tree.heading('opcode', text='Opcode')
        self.machine_tree.heading('operands', text='Operandlar')
        self.machine_tree.heading('binary', text='Binary')
        self.machine_tree.heading('comment', text='Yorum')

        self.machine_tree.column('address', width=100, anchor='e')
        self.machine_tree.column('opcode', width=100, anchor='center')
        self.machine_tree.column('operands', width=150, anchor='w')
        self.machine_tree.column('binary', width=200, anchor='center')
        self.machine_tree.column('comment', width=300, anchor='w')

        mach_scroll = ttk.Scrollbar(machine_frame, orient="vertical", command=self.machine_tree.yview)
        self.machine_tree.configure(yscrollcommand=mach_scroll.set)
        self.machine_tree.pack(side="left", fill="both", expand=True)
        mach_scroll.pack(side="right", fill="y")

        self.root.bind('<F5>', lambda e: self.convert_code())

    def add_new_page(self):
        page_num = len(self.pages) + 1
        page_name = f"Sayfa {page_num}"
        self.pages[page_name] = ""
        self.update_page_selector()
        self.page_selector.set(page_name)
        self.current_page = page_name

    def change_page(self, event=None):
        # Mevcut sayfadaki kodu kaydet
        if self.current_page:
            self.pages[self.current_page] = self.asm_text.get("1.0", "end-1c")
        
        # Yeni sayfaya geç
        new_page = self.page_selector.get()
        self.current_page = new_page
        self.asm_text.delete("1.0", "end")
        self.asm_text.insert("1.0", self.pages.get(new_page, ""))

    def update_page_selector(self):
        pages = list(self.pages.keys())
        self.page_selector['values'] = pages

    def convert_code(self):
        # Tüm sayfaları birleştir
        all_code = ""
        for page_name, code in self.pages.items():
            if code.strip():  # Boş olmayan sayfaları ekle
                all_code += f"; === {page_name} ===\n{code}\n\n"

        lines = all_code.splitlines()

        try:
            namtab, deftab = parse_macros(lines)
            expanded_code = expand_macros(lines, deftab)
            final_code = "\n".join(expanded_code)

            output, section_content, symbol_table, section_ranges, relocation_table = parse_assembly(final_code)
            generate_objtxt_dynamic(
                filepath="output.objtxt",
                elf_machine="MSP430",
                entry="0x1100",
                section_content=section_content,
                symbol_table=symbol_table,
                section_ranges=section_ranges,
                relocation_table=relocation_table
            )

            self.process_output(output, symbol_table)
            self.display_macro_tables(namtab, deftab)

            messagebox.showinfo("Başarılı", ".objtxt dosyası başarıyla oluşturuldu!")

        except Exception as e:
            messagebox.showerror("Hata", f"Çeviri hatası:\n{str(e)}")

    def process_output(self, output, symbol_table):
        self.symtab_tree.delete(*self.symtab_tree.get_children())
        for symbol, (value, sym_type) in symbol_table.items():
            self.symtab_tree.insert('', tk.END, values=(symbol, sym_type, value))

        self.machine_tree.delete(*self.machine_tree.get_children())

        for line in output.split('\n'):
            line = line.strip()
            if not line or not line.startswith('0x'):
                continue

            parts = line.split(";", 1)
            code_part = parts[0].strip()
            comment = parts[1].strip() if len(parts) > 1 else ""

            try:
                addr, rest = code_part.split(":", 1)
                addr = addr.strip()
                binary_part = rest.strip()

                hex_match = re.search(r"\(0x[0-9A-Fa-f]+\)", binary_part)
                hex_str = hex_match.group(0) if hex_match else ""
                binary_clean = re.sub(r"\(0x[0-9A-Fa-f]+\)", "", binary_part).strip()

                binary_display = f"{binary_clean} {hex_str}" if hex_str else binary_clean

                if comment:
                    comment_parts = comment.split(maxsplit=1)
                    opcode = comment_parts[0] if comment_parts else ""
                    operands = comment_parts[1] if len(comment_parts) > 1 else ""
                else:
                    opcode, operands = "", ""

                self.machine_tree.insert('', tk.END, values=(
                    addr,
                    opcode,
                    operands,
                    binary_display,
                    comment
                ))
            except:
                continue

    def display_macro_tables(self, namtab, deftab):
        self.namtab_tree.delete(*self.namtab_tree.get_children())
        self.deftab_listbox.delete(0, tk.END)

        for macro_name in namtab:
            params, size = namtab[macro_name]
            self.namtab_tree.insert('', tk.END, values=(macro_name, ', '.join(params), size))

        for macro_name, (params, body) in deftab.items():
            for line in body:
                self.deftab_listbox.insert(tk.END, f"{macro_name}: {line}")

    def clear_all(self):
        self.asm_text.delete("1.0", tk.END)
        self.symtab_tree.delete(*self.symtab_tree.get_children())
        self.namtab_tree.delete(*self.namtab_tree.get_children())
        self.deftab_listbox.delete(0, tk.END)
        self.machine_tree.delete(*self.machine_tree.get_children())

    def open_memory_popup(self):
        popup = tk.Toplevel(self.root)
        popup.title("Sanal Bellek Gözlemi")
        popup.geometry("800x500")
        ttk.Label(popup, text="Sanal Bellek (Hex Viewer)", font=self.bold_font).pack(anchor='w', padx=10, pady=5)
        desc = "Adres      " + " ".join([f"+{i*2:02X}" for i in range(8)]) + "   | ASCII"
        ttk.Label(popup, text=desc, font=("Consolas", 10, "bold")).pack(anchor='w', padx=10)
        memory_output = tk.Text(popup, height=30, width=90, font=("Consolas", 10))
        memory_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        memory_output.config(state=tk.NORMAL)

        try:
            from linking_loader import linking_loader
            vm, estab, section_ranges = linking_loader("output.objtxt")

            memory_output.delete("1.0", tk.END)
            start_addr = min(r[0] for r in section_ranges.values())
            end_addr = max(r[1] for r in section_ranges.values())

            for base in range(start_addr, end_addr, 16):  # 8 kelime (16 byte) bir satırda
                hex_values = []
                ascii_values = []
                for offset in range(0, 16, 2):
                    addr = base + offset
                    val = vm.read_word(addr)
                    hex_values.append(val)
                    # ASCII gösterimi
                    try:
                        c1 = chr(int(val[:2], 16))
                        c2 = chr(int(val[2:], 16))
                        ascii_values.append(c1 if 32 <= ord(c1) <= 126 else '.')
                        ascii_values.append(c2 if 32 <= ord(c2) <= 126 else '.')
                    except:
                        ascii_values.extend(['.', '.'])
                hex_str = " ".join(hex_values)
                ascii_str = "".join(ascii_values)
                memory_output.insert(tk.END, f"{base:04X}    {hex_str}   | {ascii_str}\n")
            memory_output.config(state=tk.DISABLED)
        except Exception as e:
            memory_output.insert(tk.END, f"Bellek gösterimi başarısız:\n{str(e)}")

    def show_memory_dump(self):
        try:
            from linking_loader import linking_loader
            vm, estab, section_ranges = linking_loader("output.objtxt")

            self.memory_output.delete("1.0", tk.END)

            # Bellek gösterimi
            for addr in range(0x1100, 0x1200, 2):
                val = vm.read_word(addr)
                self.memory_output.insert(tk.END, f"{addr:04X}: {val}\n")

            # 🔽 ESTAB tablosunu sadece 1 kez sil ve güncelle
            self.estab_tree.delete(*self.estab_tree.get_children())
            for section, data in estab.items():
                base = data.get("base", 0)
                for sym, addr in data.get("symbols", {}).items():
                    self.estab_tree.insert('', tk.END, values=(section, sym, f"0x{addr:04X}"))

        except Exception as e:
            messagebox.showerror("Hata", f"Bellek veya ESTAB gösterimi başarısız:\n{str(e)}")



if __name__ == "__main__":
    root = tk.Tk()
    app = AssemblerGUI(root)
    root.mainloop()