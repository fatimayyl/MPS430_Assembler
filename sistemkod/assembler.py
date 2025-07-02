import re

# MSP430 OPCODE TABLOSU
OPCODES = {
    "MOV": ("two_operand", "0100"), "ADD": ("two_operand", "0101"),
    "ADDC": ("two_operand", "0110"), "SUBC": ("two_operand", "0111"),
    "SUB": ("two_operand", "1000"), "CMP": ("two_operand", "1001"),
    "DADD": ("two_operand", "1010"), "BIT": ("two_operand", "1011"),
    "BIC": ("two_operand", "1100"), "BIS": ("two_operand", "1101"),
    "XOR": ("two_operand", "1110"), "AND": ("two_operand", "1111"),
    "RRC": ("single_operand", "000100000"), "SWPB": ("single_operand", "000100001"),
    "RRA": ("single_operand", "000100010"), "SXT": ("single_operand", "000100011"),
    "PUSH": ("single_operand", "000100100"), "CALL": ("single_operand", "000100101"),
    "RETI": ("single_operand", "000100110"),
    "JMP": ("jump", "001111"), "JNZ": ("jump", "001000"), "JNE": ("jump", "001000"),
    "JEQ": ("jump", "001001"), "JZ": ("jump", "001001"), "JNC": ("jump", "001010"),
    "JLO": ("jump", "001010"), "JC": ("jump", "001011"), "JHS": ("jump", "001011"),
    "JN": ("jump", "001100"), "JGE": ("jump", "001101"), "JL": ("jump", "001110")
}

# Register kodları
REGISTERS = {f"R{i}": format(i, "04b") for i in range(16)}
symbol_table = {}
definitions = {}
references = {}

section_defaults = {
    "text": 0x1100,
    "data": 0x0200,
    "bss":  0x1800
}

# === MAKRO FONKSİYONLARI ===
def parse_macros(lines):
    namtab = {}
    deftab = {}
    in_macro = False
    current_macro_name = ""
    current_params = []
    current_body = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if ".macro" in stripped:
            parts = stripped.split()
            current_macro_name = parts[0]
            current_params = parts[2:] if len(parts) > 2 else []
            in_macro = True
            current_body = []
        elif ".endm" in stripped:
            namtab[current_macro_name] = (current_params, len(current_body))
            deftab[current_macro_name] = (current_params, current_body)
            in_macro = False
        elif in_macro:
            current_body.append(stripped)

    return namtab, deftab

def expand_macros(lines, deftab):
    expanded = []
    in_macro = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if ".macro" in stripped:
            in_macro = True
            continue
        elif ".endm" in stripped:
            in_macro = False
            continue
        elif in_macro:
            continue

        tokens = stripped.split()
        if not tokens:
            continue

        macro_name = tokens[0]
        if macro_name in deftab:
            args = tokens[1:]
            params, body = deftab[macro_name]
            for body_line in body:
                expanded_line = body_line
                for i, param in enumerate(params):
                    expanded_line = expanded_line.replace(param, args[i])
                expanded.append(expanded_line)
        else:
            expanded.append(stripped)

    return expanded


def is_external_symbol(sym, current_section):
    return (
        sym in references.get(current_section, []) or
        sym in definitions.get(current_section, [])
    ) and sym not in symbol_table

def collect_labels(assembly_code):
    global symbol_table
    symbol_table = {}
    locctrs = {}
    current_section = "text"
    current_address = section_defaults[current_section]
    locctrs[current_section] = current_address

    lines = assembly_code.split("\n")

    for line in lines:
        line = line.split(';')[0].strip()
        if not line:
            continue

        if line.startswith(".text") or line.startswith(".data") or line.startswith(".bss"):
            directive, *args = line.split()
            current_section = directive[1:]
            current_address = int(args[0], 16) if args else section_defaults.get(current_section, 0x2000 + 0x100 * len(locctrs))
            locctrs[current_section] = current_address
            continue

        if line.startswith(".sect"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                current_section = parts[1].strip('"')
                current_address = locctrs.get(current_section, section_defaults.get(current_section, 0x2000 + 0x100 * len(locctrs)))
                locctrs[current_section] = current_address
            continue

        if ".usect" in line:
            match = re.match(r"^(\w+)\s+\.usect\s+\"?([\w.]+)\"?,\s*(\d+)(?:,\s*(\d+))?", line)
            if match:
                symbol = match.group(1)
                section_name = match.group(2).strip('"')
                size = int(match.group(3))
                alignment = int(match.group(4)) if match.group(4) else 1

                current_address = locctrs.get(section_name, 0x3000 + 0x100 * len(locctrs))
                if current_address % alignment != 0:
                    current_address += (alignment - (current_address % alignment))
                
                symbol_table[symbol] = (format(current_address, '04X'), "R")
                locctrs[section_name] = current_address + size
            continue

        if ".space" in line:
            label_match = re.match(r"^(\w+):\s*\.space\s+(\d+)", line)
            if label_match:
                symbol = label_match.group(1)
                size = int(label_match.group(2))
                symbol_table[symbol] = (format(current_address, '04X'), "R")
                current_address += size
                locctrs[current_section] = current_address
            continue

        label_match = re.match(r"^(\w+):", line)
        if label_match:
            symbol = label_match.group(1)
            symbol_table[symbol] = (format(current_address, '04X'), "R")

        # Komut veya veri tahmini (2 byte)
        if not any(x in line for x in [".set", ".equ"]):
            current_address += 2
            locctrs[current_section] = current_address

    return symbol_table


def get_addressing_mode(operand):
    operand = operand.strip()
    if operand in REGISTERS:
        return REGISTERS[operand], "0", "00", False
    elif re.match(r"@\w+\+", operand):  # indirect autoinc
        reg = operand[1:-1]
        return REGISTERS.get(reg, "0000"), "0", "11", False
    elif re.match(r"@\w+", operand):  # indirect
        reg = operand[1:]
        return REGISTERS.get(reg, "0000"), "0", "10", False
    elif re.match(r"#\w+", operand):  # immediate (literal veya label)
        return "0000", "0", "11", True
    elif re.match(r"\d+\(\w+\)", operand):  # indexed
        reg_match = re.findall(r"\((R\d+)\)", operand)
        if reg_match:
            return REGISTERS.get(reg_match[0], "0000"), "1", "01", True
    elif re.match(r"&\w+", operand):  # absolute
        return "0000", "1", "01", True
    return "0000", "0", "00", False



def detect_bw_suffix(opcode):
    if ".B" in opcode:
        return opcode.replace(".B", ""), "1"
    return opcode.replace(".W", ""), "0"

def clean_operand(operand):
    operand = re.sub(r'\.(W|B)', '', operand)
    operand = re.sub(r'[,\s]+$', '', operand.strip())
    return operand

# Mevcut parse_assembly fonksiyonu güncellenmiş versiyonuyla değiştirilir.
# Bu sürüm, text_section, data_section, section_ranges gibi ek alanlar toplayarak
# generate_objtxt fonksiyonu ile kullanılabilir hale getirir.

def parse_assembly(assembly_code):
    global symbol_table, definitions, references

    definitions = {}
    references = {}

    # ----------------------------------------
    # 1. Yorumları ayıkla, boş satırları sil
    # ----------------------------------------
    raw_lines = [line.split(';')[0].strip() for line in assembly_code.splitlines() if line.strip()]

    # ----------------------------------------
    # 2. Makro tanımlarını al
    # ----------------------------------------
    namtab, deftab = parse_macros(raw_lines)

    # ----------------------------------------
    # 3. Makro çağrılarını genişlet
    # ----------------------------------------
    expanded_lines = expand_macros(raw_lines, deftab)
    expanded_code = "\n".join(expanded_lines)

    # ----------------------------------------
    # 4. Genişletilmiş koddan etiketleri topla
    # ----------------------------------------
    symbol_table = collect_labels(expanded_code)

    # ----------------------------------------
    # 5. Kod çözümlemeye hazırlan
    # ----------------------------------------
    lines = expanded_code.split("\n")

    section_defaults = {
        "text": 0x1100,
        "data": 0x0200,
        "bss":  0x1800
    }

    locctrs = {}
    current_section = "text"
    current_address = section_defaults[current_section]
    locctrs[current_section] = current_address
    constants = {}
    machine_code = []
    relocation_table = []

    # ➤ Bundan sonrası: satır satır opcode çözümlemesi
    # ...


    for line in lines:
        line = line.split(';')[0].strip()
        if not line:
            continue

        if line.startswith(".sect"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                current_section = parts[1].strip('"')
                if current_section not in locctrs:
                    locctrs[current_section] = section_defaults.get(current_section, 0x2000 + 0x100 * len(locctrs))
            current_address = locctrs[current_section]
            machine_code.append(f"; Yeni bölüm: {current_section} (adres {format(current_address, '04X')})")
            definitions.setdefault(current_section, [])
            references.setdefault(current_section, [])
            continue

        if line.startswith(".def") or line.startswith(".global"):
            symbols = [s.strip() for s in re.split(r"[\s,]+", line.split(None, 1)[1]) if s.strip()]
            definitions.setdefault(current_section, []).extend(symbols)
            machine_code.append(f"; .def/.global: {', '.join(symbols)}")
            continue

        if line.startswith(".ref"):
            symbols = [s.strip() for s in re.split(r"[\s,]+", line.split(None, 1)[1]) if s.strip()]
            references.setdefault(current_section, []).extend(symbols)
            machine_code.append(f"; .ref: {', '.join(symbols)}")
            continue

        if ".usect" in line:
            match = re.match(r"^(\w+)\s+\.usect\s+\"?([\w.]+)\"?,\s*(\d+)(?:,\s*(\d+))?", line)
            if match:
                symbol = match.group(1)
                section_name = match.group(2).strip('"')
                size = int(match.group(3))
                alignment = int(match.group(4)) if match.group(4) else 1

                current_address = locctrs.get(section_name, 0x3000 + 0x100 * len(locctrs))
                if current_address % alignment != 0:
                    current_address += (alignment - (current_address % alignment))

                symbol_table[symbol] = (format(current_address, '04X'), "R")
                locctrs[section_name] = current_address + size
                machine_code.append(f"0x{format(current_address, '04X')}: .usect \"{section_name}\" {size} byte -> {symbol}")
                current_address = locctrs[section_name]
            continue

        if line.startswith(".text") or line.startswith(".data") or line.startswith(".bss"):
            directive, *args = line.split()
            current_section = directive[1:]
            if args:
                current_address = int(args[0], 16)
            else:
                current_address = section_defaults.get(current_section, 0x1000)
            locctrs[current_section] = current_address
            machine_code.append(f"@{format(current_address, '04X')} ; .{current_section} başlangıcı")
            continue

        if ".set" in line or ".equ" in line:
            match = re.match(r"^(\w+)\s+\.(set|equ)\s+(.+)", line)
            if match:
                name = match.group(1)
                expr = match.group(3)
                try:
                    expr_eval = expr.replace('$', str(current_address))
                    context = {
                        k: int(v[0], 16) if isinstance(v, tuple) else int(v, 16)
                        for k, v in symbol_table.items() if isinstance(v, (tuple, str))
                    }
                    value = eval(expr_eval, {}, context | constants)
                    ref_symbols = re.findall(r'\b\w+\b', expr)
                    ref_types = [symbol_table[sym][1] for sym in ref_symbols if sym in symbol_table and isinstance(symbol_table[sym], tuple)]
                    sym_type = "A" if (len(ref_types) != 1 or ref_types[0] != "R") else "R"
                    constants[name] = value
                    symbol_table[name] = (format(value, '04X'), sym_type)
                    machine_code.append(f"; {name} = 0x{value:04X} ({sym_type} olarak tanımlandı)")
                except Exception as e:
                    machine_code.append(f"; {name} tanımlanamadı: {expr} ({e})")
            continue

        if ".space" in line:
            label_match = re.match(r"^(\w+):\s*.space\s+(.*)", line)
            if label_match:
                label = label_match.group(1)
                size = int(label_match.group(2).strip())
                machine_code.append(f"0x{format(current_address, '04X')}: .space {size} byte ; .bss -> {label}")
                current_address += size
            else:
                size = int(line.replace(".space", "").strip())
                machine_code.append(f"0x{format(current_address, '04X')}: .space {size} byte")
                current_address += size
            locctrs[current_section] = current_address
            continue
                # .word işle

        if current_section == "data" and ".word" in line:
            label_match = re.match(r"^(\w+):\s*.word\s+(.*)", line)
            if label_match:
                label = label_match.group(1)
                values = label_match.group(2).split(",")
                symbol_table[label] = (format(current_address, '04X'), "R")
            else:
                values = line.replace(".word", "").split(",")

            for val in values:
                val = val.strip()
                try:
                    # Relocation gerekiyor mu kontrol et
                    if val not in constants and not re.match(r"^0x[0-9a-fA-F]+$", val) and not val.isdigit():
                        relocation_table.append({
                            "symbol": val,
                            "address": current_address,
                            "section": current_section,
                            "type": "relative"
                        })

                    # Değeri hesapla (varsa sabit, yoksa sıfırla devam)
                    if val in constants:
                        num = constants[val]
                    elif re.match(r"^0x[0-9a-fA-F]+$", val):
                        num = int(val, 16)
                    elif val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
                        num = int(val)
                    else:
                        num = 0  # Relocation olacaksa bu alan loader tarafından doldurulacak

                    num = num & 0xFFFF  # 16 bit sınırı

                    machine_code.append(f"0x{format(current_address, '04X')}: .word 0x{num:04X}")
                    current_address += 2

                except Exception as e:
                    machine_code.append(f"; .word işlenemedi: {val} ({e})")
            locctrs[current_section] = current_address
            continue
        

        
        if current_section == "data" and ".byte" in line:
            label_match = re.match(r"^(\w+):\s*.byte\s+(.*)", line)
            if label_match:
                label = label_match.group(1)
                values = label_match.group(2).split(",")
                symbol_table[label] = (format(current_address, '04X'), "R")
            else:
                values = line.replace(".byte", "").split(",")

            for val in values:
                val = val.strip()
                try:
                    if re.match(r"^'.'$", val):
                        num = ord(val[1])
                    elif re.match(r'^".+"$', val):
                        for c in val.strip('"'):
                            machine_code.append(f"0x{format(current_address, '04X')}: .byte 0x{ord(c):02X}")
                            current_address += 1
                        continue
                    elif val in constants:
                        num = constants[val]
                    elif re.match(r"^0x[0-9a-fA-F]+$", val):
                        num = int(val, 16)
                    elif val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
                        num = int(val)
                    else:
                        num = 0
                    num = num & 0xFF
                    machine_code.append(f"0x{format(current_address, '04X')}: .byte 0x{num:02X}")
                    current_address += 1
                except Exception as e:
                    machine_code.append(f"; .byte işlenemedi: {val} ({e})")
            locctrs[current_section] = current_address
            continue



        label_match = re.match(r"^(\w+):\s*(.*)", line)
        if label_match:
            symbol = label_match.group(1)
            symbol_table[symbol] = (format(current_address, '04X'), "R")
            line = label_match.group(2).strip()

        tokens = line.split(maxsplit=1)
        if not tokens:
            continue

        opcode, bw_bit = detect_bw_suffix(tokens[0].upper())
        if opcode in OPCODES:
            op_type, binary_opcode = OPCODES[opcode]
            if op_type == "two_operand" and len(tokens) > 1:
                operands = re.split(r'\s*,\s*', tokens[1])
                if len(operands) == 2:
                    src = clean_operand(operands[0])
                    dst = clean_operand(operands[1])
                    src_bin, Ad, As, src_extra = get_addressing_mode(src)
                    dst_bin, _, _, dst_extra = get_addressing_mode(dst)

                    binary_str = f"{binary_opcode}{src_bin}{Ad}{bw_bit}{As}{dst_bin}"
                    hex_str = format(int(binary_str, 2), "04X")
                    machine_code.append(f"0x{format(current_address, '04X')}: {binary_str} (0x{hex_str}) ; {line}")
                    current_address += 2

                    for operand, needs_extra in [(src, src_extra), (dst, dst_extra)]:
                        if needs_extra:
                            sym = operand.strip("#&")
                            try:
                                # ➕ Relocation gerektiriyorsa tabloya ekle
                                if not sym.isdigit() and not re.match(r"^0x[0-9a-fA-F]+$", sym):
                                    relocation_table.append({
                                        "symbol": sym,
                                        "address": current_address,
                                        "section": current_section,
                                        "type": "relative"
                                    })

                                # ➕ Değeri çözümle
                                if is_external_symbol(sym, current_section):
                                    val = "0000!"
                                elif sym in constants:
                                    val = f"{constants[sym]:04X}"
                                elif sym in symbol_table:
                                    val = symbol_table[sym][0]
                                elif re.match(r"^0x[0-9a-fA-F]+$", sym):
                                    val = f"{int(sym, 16):04X}"
                                elif sym.isdigit():
                                    val = f"{int(sym):04X}"
                                else:
                                    val = "XXXX"
                            except:
                                val = "ERR!"
                            machine_code.append(f"0x{format(current_address, '04X')}: {val:<4} (0x{val}) ; {operand} için ek veri")

                            current_address += 2

            elif op_type == "single_operand" and len(tokens) > 1:
                operand = clean_operand(tokens[1])
                src_bin, Ad, As, src_extra = get_addressing_mode(operand)
                binary_str = f"{binary_opcode}{bw_bit}{As}{src_bin}"
                hex_str = format(int(binary_str, 2), "04X")
                machine_code.append(f"0x{format(current_address, '04X')}: {binary_str} (0x{hex_str}) ; {line}")
                current_address += 2

                if src_extra:
                    sym = operand.strip("#&")
                    try:
                        if is_external_symbol(sym, current_section):
                            val = "0000!"
                        elif sym in constants:
                            val = f"{constants[sym]:04X}"
                        elif sym in symbol_table:
                            val = symbol_table[sym][0]
                        elif re.match(r"^0x[0-9a-fA-F]+$", sym):
                            val = f"{int(sym, 16):04X}"
                        elif sym.isdigit():
                            val = f"{int(sym):04X}"
                        else:
                            val = "XXXX"
                    except:
                        val = "ERR!"
                    machine_code.append(f"0x{format(current_address, '04X')}: {val:<4} (0x{val}) ; {operand} için ek veri")

                    current_address += 2

            elif op_type == "jump" and len(tokens) > 1:
                label = tokens[1].strip()

                # Relocation gerektiriyorsa tabloya ekle
                if label not in symbol_table:
                    relocation_table.append({
                        "symbol": label,
                        "address": current_address,
                        "section": current_section,
                        "type": "relative"
                    })
                    offset = 0  # şimdilik sıfırla devam
                else:
                    target_address = int(symbol_table[label][0], 16)
                    offset = target_address - (current_address + 2)

                offset_bin = format(offset & 0x3FF, '010b')
                binary_str = f"{binary_opcode}{offset_bin}"
                hex_str = format(int(binary_str, 2), "04X")

                machine_code.append(f"0x{format(current_address, '04X')}: {binary_str} (0x{hex_str}) ; {line}")
                current_address += 2


            locctrs[current_section] = current_address

    machine_code.append("\n; Etiketler:")
    machine_code.append("; Symbol    Type   Value")
    for label, val in symbol_table.items():
        if isinstance(val, tuple):
            machine_code.append(f"{label:<10} {val[1]}      {val[0]}")
        else:
            machine_code.append(f"{label:<10} ?      {val}")

    if definitions or references:
        machine_code.append("\n; Control Sections:")
        for sect in definitions:
            machine_code.append(f"; Section \"{sect}\"")
            if definitions[sect]:
                machine_code.append(f";   .def: {', '.join(definitions[sect])}")
            if references.get(sect):
                machine_code.append(f";   .ref: {', '.join(references[sect])}")

    # --- EK: objtxt için veri çıkarımı ---
    section_content = {}
    for sect in locctrs:
        section_content[sect] = []

    for line in machine_code:
        if re.match(r"^0x[0-9A-Fa-f]+: ", line):
            addr = int(line.split(":")[0], 16)
            hex_match = re.search(r"\(0x([0-9A-Fa-f]{4})\)", line) or \
            re.search(r"\.word\s+0x([0-9A-Fa-f]{4})", line) or \
            re.search(r"\.byte\s+0x([0-9A-Fa-f]{2})", line)
            if hex_match:
                hex_val = hex_match.group(1)
                for sect in locctrs:
                    start = section_defaults.get(sect, 0)
                    end = locctrs[sect]
                    if start <= addr < end:
                        section_content[sect].append((addr, hex_val))
                        break

    section_ranges = {}
    for sect in locctrs:
        start = None
    # machine_code içinde o section için ilk adresi bul
        for line in machine_code:
            if line.startswith(f"; Yeni bölüm: {sect}"):
                match = re.search(r"adres ([0-9A-Fa-f]{4})", line)
                if match:
                    start = int(match.group(1), 16)
                    break
        if start is None:
        # .usect'ler machine_code içinde görünmediği için doğrudan hesaplanır
            for line in machine_code:
                if f'.usect "{sect}"' in line:
                    match = re.match(r"0x([0-9A-Fa-f]{4}):", line)
                    if match:
                        start = int(match.group(1), 16)
                        break
        if start is None:
            start = section_defaults.get(sect, 0)
        end = locctrs[sect]
        section_ranges[sect] = (start, end)


    return "\n".join(machine_code), section_content, symbol_table, section_ranges, relocation_table


def generate_objtxt_dynamic(
    filepath: str,
    elf_machine: str,
    entry: str,
    section_content: dict,
    symbol_table: dict,
    section_ranges: dict,
    relocation_table: list
):
    def section_header(idx, name, type_, addr, size):
        return f"[ {idx}] .{name:<12} {type_:<10} {addr:08X} {size:08X}"

    lines = []
    lines.append("ELF Object Dosyası")
    lines.append("*\n")
    lines.append("ELF Header:")
    lines.append("  Data:                            2's complement, little endian")
    lines.append("  Type:                            REL (Relocatable file)")
    lines.append(f"  Machine:                         {elf_machine}")
    lines.append(f"  Entry:                           {entry}\n")
    lines.append("\nProgram Entry Point:")
    lines.append(f"  Entry address: {entry}")


    # Section headers
    lines.append("Section Headers:")
    lines.append("  [Nr] Name         Type       Addr     Size")

    headers = []
    for idx, section_name in enumerate(section_content.keys()):
        start, end = section_ranges.get(section_name, (0, 0))
        size = end - start
        headers.append(section_header(idx, section_name, "PROGBITS", start, size))
    lines.extend(headers)
    lines.append("")

    # Section content
    for name, items in section_content.items():
        lines.append(f".{name} Section (Machine Code):")
        lines.append("  Address | Code")
        for addr, val in items:
            lines.append(f"  {addr:04X}    | {val}")
        lines.append("")

    # Symbol table
    lines.append(".symtab Section (Symbol Table):")
    lines.append("  Symbol       | Value | Type")
    for sym, (val, sym_type) in symbol_table.items():
        vtype = "relative" if sym_type == "R" else "absolute" if sym_type == "A" else "external"
        lines.append(f"  {sym:<12}| {val} | {vtype}")

    # .reloc bölümü
    lines.append("\n.reloc Section (Relocation Table):")
    lines.append("  Symbol       | Address | Section   | Type")
    for reloc in relocation_table:
        lines.append(
            f"  {reloc['symbol']:<12}| 0x{reloc['address']:04X} | {reloc['section']:<9}| {reloc['type']}"
        )

    # ESTAB (External Symbol Table)
    lines.append("\n.estab Section (External Symbol Table):")
    lines.append("  Section    | Base   | Symbol       | Address")
    lines.append("  -----------|--------|--------------|---------")

    for section, (start, _) in section_ranges.items():
        for sym, (addr, typ) in symbol_table.items():
            if typ == "R" and int(addr, 16) >= start:
                lines.append(f"  {section:<11}| 0x{start:04X} | {sym:<12}| 0x{addr}")


    with open(filepath, "w") as f:
        f.write("\n".join(lines))
    return filepath

# === Sanal Bellek Yapısı (VirtualMemory) ===

class VirtualMemory:
    def __init__(self):
        self.memory = {}
        self.sections = {
            "text": (0x1100, 0x2000),  # Program kodu
            "data": (0x0200, 0x1000),  # Veri
            "bss":  (0x1800, 0x2000)   # Başlatılmamış veri
        }
        self.initialized = False

    def initialize(self):
        """Belleği sıfırla ve bölümleri ayarla."""
        self.memory.clear()
        self.initialized = True

    def load_word(self, addr, word):
        """16-bit kelimeyi belleğe yükle (hex string olarak)."""
        try:
            # Adres kontrolü
            if not isinstance(addr, int):
                raise ValueError(f"Geçersiz adres tipi: {type(addr)}")
            
            # Kelime kontrolü
            if not isinstance(word, str) or len(word) != 4:
                raise ValueError(f"Geçersiz kelime formatı: {word}")
            
            # Hex kontrolü
            int(word, 16)  # Hex formatında mı kontrol et
            
            # Bölüm kontrolü
            in_section = False
            for section, (start, end) in self.sections.items():
                if start <= addr < end:
                    in_section = True
                    break
            
            if not in_section:
                raise ValueError(f"Adres {addr:04X} herhangi bir bölümde değil")
            
            # Belleğe yükle
            self.memory[addr] = word.upper().zfill(4)
            return True
            
        except Exception as e:
            print(f"[!] Bellek yükleme hatası: {e}")
            return False

    def read_word(self, addr):
        """Verilen adresteki 16-bit kelimeyi oku."""
        try:
            if not isinstance(addr, int):
                raise ValueError(f"Geçersiz adres tipi: {type(addr)}")
            
            # Adres kontrolü
            for section, (start, end) in self.sections.items():
                if start <= addr < end:
                    return self.memory.get(addr, "0000")
            
            raise ValueError(f"Adres {addr:04X} herhangi bir bölümde değil")
            
        except Exception as e:
            print(f"[!] Bellek okuma hatası: {e}")
            return "0000"

    def dump(self, start=None, end=None, section=None):
        """Bellek alanını göster."""
        try:
            if section:
                if section not in self.sections:
                    raise ValueError(f"Geçersiz bölüm: {section}")
                start, end = self.sections[section]
            elif start is None or end is None:
                # Tüm belleği göster
                for section, (s, e) in self.sections.items():
                    print(f"\n=== {section.upper()} Bölümü ({s:04X}-{e:04X}) ===")
                    self.dump(s, e)
                return

            print(f"\n=== Bellek Dump ({start:04X}-{end:04X}) ===")
            print("Adres  | Değer  | ASCII")
            print("-------|--------|------")
            
            for addr in range(start, end, 2):
                val = self.read_word(addr)
                # ASCII gösterimi için
                try:
                    ascii_val = chr(int(val[:2], 16)) + chr(int(val[2:], 16))
                    ascii_val = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in ascii_val)
                except:
                    ascii_val = ".."
                print(f"{addr:04X}  | {val}  | {ascii_val}")
                
        except Exception as e:
            print(f"[!] Bellek dump hatası: {e}")

    def get_section_info(self):
        """Bölüm bilgilerini göster."""
        print("\n=== Bellek Bölümleri ===")
        for section, (start, end) in self.sections.items():
            used = sum(1 for addr in range(start, end, 2) if addr in self.memory)
            total = (end - start) // 2
            print(f"{section:6} | {start:04X}-{end:04X} | {used}/{total} kelime kullanıldı")

    def verify_memory(self):
        """Bellek bütünlüğünü kontrol et."""
        errors = []
        for addr, val in self.memory.items():
            # Adres kontrolü
            in_section = False
            for section, (start, end) in self.sections.items():
                if start <= addr < end:
                    in_section = True
                    break
            if not in_section:
                errors.append(f"Adres {addr:04X} herhangi bir bölümde değil")
            
            # Değer kontrolü
            try:
                int(val, 16)
            except:
                errors.append(f"Adres {addr:04X}'deki değer geçersiz: {val}")
        
        return errors

def linking_loader(filepath):
    """Nesne dosyasını sanal belleğe yükle."""
    vm = VirtualMemory()
    vm.initialize()
    current_section = None
    loading = False
    errors = []

    try:
        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                # Bölüm başlangıcı
                if line.endswith("Section (Machine Code):"):
                    current_section = line.split()[0].lstrip(".")
                    loading = True
                    continue

                # Makine kodu satırı
                if loading and "|" in line:
                    try:
                        parts = line.split("|")
                        addr = int(parts[0].strip(), 16)
                        code = parts[1].strip()
                        if len(code) == 4:  # 16-bit kelime
                            if not vm.load_word(addr, code):
                                errors.append(f"Satır {line_num}: Yükleme hatası - {line}")
                    except Exception as e:
                        errors.append(f"Satır {line_num}: {e} - {line}")
                        continue

                # Başka bölüme geçildiğinde yüklemeyi durdur
                if line.startswith(".symtab") or line.startswith(".reloc") or line.startswith(".estab"):
                    loading = False

        # Bellek doğrulama
        memory_errors = vm.verify_memory()
        if memory_errors:
            errors.extend(memory_errors)

        # Sonuçları göster
        if errors:
            print("\n=== Yükleme Hataları ===")
            for error in errors:
                print(f"[!] {error}")
        else:
            print("\n[+] Dosya başarıyla yüklendi")
            vm.get_section_info()
            vm.dump()

    except Exception as e:
        print(f"[!] Dosya yükleme hatası: {e}")

    return vm

def load_memory_from_objtxt(filepath="output.objtxt"):
    """Nesne dosyasından verileri okuyarak sanal belleğe yükler."""
    vm = VirtualMemory()
    vm.initialize()
    in_section = False
    errors = []

    try:
        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                if line.strip().endswith("Section (Machine Code):"):
                    in_section = True
                    continue

                if in_section:
                    if not line.strip():  # boş satırla section bitiyor
                        in_section = False
                        continue

                    if "|" in line:
                        parts = line.strip().split("|")
                        if len(parts) >= 2:
                            addr_str = parts[0].strip()
                            val_str = parts[1].strip()

                            try:
                                addr = int(addr_str, 16)
                                if not vm.load_word(addr, val_str):
                                    errors.append(f"Satır {line_num}: Yükleme hatası - {line}")
                            except ValueError as e:
                                errors.append(f"Satır {line_num}: {e} - {line}")
                                continue

        # Bellek doğrulama
        memory_errors = vm.verify_memory()
        if memory_errors:
            errors.extend(memory_errors)

        # Sonuçları göster
        if errors:
            print("\n=== Yükleme Hataları ===")
            for error in errors:
                print(f"[!] {error}")
        else:
            print("\n[+] Dosya başarıyla yüklendi")
            vm.get_section_info()
            vm.dump()

    except Exception as e:
        print(f"[!] Dosya yükleme hatası: {e}")

    return vm