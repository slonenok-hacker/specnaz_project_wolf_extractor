#!/usr/bin/env python3
"""
UFF 1.0 Extractor для main04.bfs — Specnaz: Project Wolf.
Формат: 12-байтные записи, маппинг имён через cur_idx (последний байт записи).
"""

import struct
import os
import sys

def deobfuscate(data, offset, size):
    result = bytearray(size)
    for i in range(size):
        result[i] = ((data[offset + i] - i) & 0xFF) ^ 0x16
    return bytes(result)

def parse_names(data, start, end):
    names = []
    pos = start
    while pos < end:
        nul = data.find(b'\x00', pos, end)
        if nul < 0:
            break
        name_bytes = data[pos:nul]
        if len(name_bytes) == 0:
            pos = nul + 1
            continue
        try:
            name = name_bytes.decode('ascii')
            if all(32 <= b < 127 for b in name_bytes) and len(name) >= 1:
                names.append(name)
            else:
                names.append(None)
        except:
            names.append(None)
        pos = nul + 1
    return names

def extract_main04(bfs_path, output_dir):
    with open(bfs_path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    dir_offset = struct.unpack_from('<I', data, file_size - 4)[0]
    dir_end = file_size - 4

    num_records = struct.unpack_from('<I', data, dir_offset)[0]
    records_start = dir_offset + 8
    records_size = num_records * 12
    names_start = records_start + records_size

    print(f"Файл: {bfs_path}")
    print(f"Размер: {file_size} байт")
    print(f"Записей: {num_records}")
    print(f"Записи: 0x{records_start:X} — 0x{names_start:X} ({records_size} байт)")
    print(f"Имена: 0x{names_start:X} — 0x{dir_end:X} ({dir_end - names_start} байт)")

    names = parse_names(data, names_start, dir_end)
    valid_names = [n for n in names if n is not None]
    print(f"Имён: {len(valid_names)}")

    # Парсинг 12-байтных записей
    file_entries = []
    for i in range(num_records):
        off = records_start + i * 12
        if off + 12 > names_start:
            break
        if data[off + 1] != 0xFF:
            continue
        offset = struct.unpack_from('<I', data, off + 3)[0]
        size = struct.unpack_from('<I', data, off + 7)[0]
        cur_idx = data[off + 11]
        if 8 <= offset < file_size and 0 < size < file_size and offset + size <= file_size:
            name = names[cur_idx] if cur_idx < len(names) and names[cur_idx] else f"unknown_{i}.bin"
            file_entries.append((offset, size, name))

    print(f"Файлов к извлечению: {len(file_entries)}")

    os.makedirs(output_dir, exist_ok=True)
    extracted = 0
    errors = 0
    seen_names = {}

    for offset, size, name in file_entries:
        if name in seen_names:
            seen_names[name] += 1
            base, ext = os.path.splitext(name)
            name = f"{base}_{seen_names[name]}{ext}"
        else:
            seen_names[name] = 0

        file_data = deobfuscate(data, offset, size)

        safe_name = name.replace('/', os.sep).replace('\\', os.sep)
        out_path = os.path.join(output_dir, safe_name)
        out_subdir = os.path.dirname(out_path)
        if out_subdir and not os.path.exists(out_subdir):
            os.makedirs(out_subdir, exist_ok=True)

        try:
            with open(out_path, 'wb') as out:
                out.write(file_data)
            extracted += 1
            if extracted <= 25:
                sig = file_data[:4] if len(file_data) >= 4 else b''
                sig_str = ''
                if sig[:4] == b'RIFF': sig_str = ' [WAV]'
                elif sig[:4] == b'DDS ': sig_str = ' [DDS]'
                elif sig[:8] == b'\x89PNG\r\n\x1a\n': sig_str = ' [PNG]'
                elif sig[:2] == b'\xff\xd8': sig_str = ' [JPEG]'
                elif sig[:4] == b'OggS': sig_str = ' [OGG]'
                elif sig[:2] == b'BM': sig_str = ' [BMP]'
                print(f"  {name} ({size} байт){sig_str}")
        except Exception as e:
            print(f"  ОШИБКА: {name} — {e}")
            errors += 1

    print(f"\nИзвлечено: {extracted}, ошибок: {errors}")
    print(f"Папка: {output_dir}/")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Использование: python uff_extract_main04.py <input.bfs> [output_dir]")
        sys.exit(1)
    bfs_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'extracted_main04'
    extract_main04(bfs_path, output_dir)
