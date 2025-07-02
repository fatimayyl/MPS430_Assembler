# === linking_loader.py ===
import re
from assembler import VirtualMemory

def parse_objtxt(filepath):
    """output.objtxt dosyasini parcalar."""
    sections = {}
    estab = {}
    reloc = []

    with open(filepath, "r") as f:
        lines = f.readlines()

    current_section = None
    mode = None
    for line in lines:
        line = line.strip()
        if line.startswith(".") and "Section (Machine Code)" in line:
            current_section = line.split()[0][1:]
            sections[current_section] = []
            mode = "section"
            continue
        elif line.startswith(".reloc"):
            mode = "reloc"
            continue
        elif line.startswith(".estab"):
            mode = "estab"
            continue
        if "--------" in line:
            continue


        if mode == "section" and re.match(r"^[0-9A-Fa-f]+\s+\|\s+[0-9A-Fa-f]+", line):
            parts = line.split("|")
            addr = int(parts[0].strip(), 16)
            val = parts[1].strip().upper()
            sections[current_section].append((addr, val))

        elif mode == "reloc" and "|" in line and not line.startswith("Symbol"):
            parts = [p.strip() for p in line.split("|")]
            reloc.append({
                "symbol": parts[0],
                "address": int(parts[1], 16),
                "section": parts[2],
                "type": parts[3]
            })

        elif mode == "estab" and "|" in line and not line.startswith("Section"):
            parts = [p.strip() for p in line.split("|")]
            section = parts[0]
            base = int(parts[1], 16)
            symbol = parts[2]
            address = int(parts[3], 16)

            if section not in estab:
                estab[section] = {"base": base, "symbols": {}}
            estab[section]["symbols"][symbol] = address



    return sections, reloc, estab

def linking_loader(objtxt_path):
    memory = VirtualMemory()
    memory.initialize()  # Belleği sıfırla ve hazırlık yap

    sections, reloc_table, estab = parse_objtxt(objtxt_path)

    # 1. Belleğe makine kodlarını yükle
    for section_name, content in sections.items():
        for addr, val in content:
            success = memory.load_word(addr, val)
            if not success:
                print(f"[!] Belleğe yükleme hatası: {addr:04X} -> {val}")

    # 2. ESTAB'tan symbol -> address eşlemesi oluştur
    symbol_dict = {}
    for section in estab:
        data = estab.get(section, {})
        symbols = data.get("symbols", {})
        for sym, addr in symbols.items():
            symbol_dict[sym] = addr

    # 3. Relocation işlemleri (reloc tablosu varsa)
    for r in reloc_table:
        symbol = r['symbol']
        addr = r['address']
        if symbol in symbol_dict:
            val = format(symbol_dict[symbol], "04X")
            memory.load_word(addr, val)
        else:
            memory.load_word(addr, "DEAD")  # Sembol yoksa dummy yükle
            print(f"[!] Relocation hatası: {symbol} sembolü bulunamadı, 0x{addr:04X} adresine DEAD yüklendi")

    # Section aralıklarını hesapla:
    section_ranges = {}
    for sect in sections:
        addresses = [addr for addr, _ in sections[sect]]
        if addresses:
            section_ranges[sect] = (min(addresses), max(addresses)+2)

    return memory, estab, section_ranges