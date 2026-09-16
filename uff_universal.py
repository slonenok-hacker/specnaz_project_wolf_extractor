#!/usr/bin/env python3
"""
UFF 1.0 Universal Extractor для Specnaz: Project Wolf.
Автоматически определяет формат архивов main01-main04.bfs.
"""

import struct
import os
import sys

def deobfuscate(data, offset, size):
    """Снимает обфускацию: decoded[i] = (stored[i] - i) & 0xFF ^ 0x16"""
    result = bytearray(size)
    for i in range(size):
        result[i] = ((data[offset + i] - i) & 0xFF) ^ 0x16
    return bytes(result)

def parse_names(data, start, end):
    """Парсит null-terminated ASCII строки."""
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

def extract_uff(bfs_path, output_dir):
    with open(bfs_path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    dir_offset = struct.unpack_from('<I', data, file_size - 4)[0]
    dir_end = file_size - 4
    dir_size = dir_end - dir_offset

    field1 = struct.unpack_from('<I', data, dir_offset)[0]
    field2 = struct.unpack_from('<I', data, dir_offset + 4)[0]

    print(f"Файл: {bfs_path}")
    print(f"Размер: {file_size} байт")
    print(f"Заголовок: field1={field1}, field2={field2}")

    records_start = dir_offset + 8

    best_cfg = None
    best_mapped = 0

    # Пробуем оба поля заголовка как количество записей
    for num_records in [field1, field2]:
        records_size = num_records * 16
        if records_size + 8 > dir_size:
            continue

        names_area_start = records_start + records_size
        names_area_size = dir_end - names_area_start

        if names_area_size < 4:
            continue

        # Пробуем с 4-байтным префиксом и без него
        for prefix_size in [4, 0]:
            if prefix_size >= names_area_size:
                continue

            if prefix_size == 4:
                prefix_val = struct.unpack_from('<I', data, names_area_start)[0]
                # Префикс должен быть ≈ размеру оставшихся имён
                if abs(prefix_val - (names_area_size - 4)) > 100:
                    continue

            actual_names_start = names_area_start + prefix_size
            names = parse_names(data, actual_names_start, dir_end)
            valid_names = [n for n in names if n is not None]

            if len(valid_names) < 2:
                continue

            if len(valid_names) / max(len(names), 1) < 0.7:
                continue

            # Считаем файловые записи (FFFF на позициях 2-3)
            file_records = []
            for i in range(num_records):
                off = records_start + i * 16
                if off + 16 > names_area_start:
                    break
                f1 = struct.unpack_from('<H', data, off + 2)[0]
                if f1 != 0xFFFF:
                    continue
                offset = struct.unpack_from('<I', data, off + 6)[0]
                size = struct.unpack_from('<I', data, off + 10)[0]
                parent = struct.unpack_from('<H', data, off + 14)[0]
                if 8 <= offset < file_size and 0 < size < file_size and offset + size <= file_size:
                    file_records.append((offset, size, parent))

            if not file_records:
                continue

            # Сопоставляем имена через parent
            mapped = sum(1 for _, _, p in file_records
                         if p < len(names) and names[p] is not None)

            if mapped > best_mapped:
                best_mapped = mapped
                best_cfg = {
                    'num_records': num_records,
                    'prefix_size': prefix_size,
                    'names': names,
                    'file_records': file_records,
                    'mapped': mapped,
                }

    if not best_cfg or best_mapped == 0:
        print("Не удалось определить формат архива.")
        return

    cfg = best_cfg
    names = cfg['names']
    print(f"\nНайдена конфигурация:")
    print(f"  Записей: {cfg['num_records']}, файл-записей: {len(cfg['file_records'])}")
    print(f"  Имён: {len([n for n in names if n])}, сопоставлено: {cfg['mapped']}")

    # Извлечение
    os.makedirs(output_dir, exist_ok=True)
    extracted = 0
    errors = 0
    seen_names = {}

    for offset, size, parent in cfg['file_records']:
        if parent < len(names) and names[parent] is not None:
            name = names[parent]
        else:
            name = f"unknown_{extracted}.bin"

        # Дубликаты → добавляем суффикс
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
        print("Использование: python uff_universal.py <input.bfs> [output_dir]")
        sys.exit(1)
    bfs_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'extracted'
    extract_uff(bfs_path, output_dir)
