#!/usr/bin/env python3
"""
UFF 1.0 Extractor v6 — финальная версия для Specnaz: Project Wolf.
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

def extract_uff(bfs_path, output_dir):
    with open(bfs_path, 'rb') as f:
        data = f.read()
    
    file_size = len(data)
    
    # Указатель на директорию — последние 4 байта
    dir_offset = struct.unpack_from('<I', data, file_size - 4)[0]
    dir_end = file_size - 4
    
    # Заголовок директории
    num_entries = struct.unpack_from('<I', data, dir_offset)[0]
    num2 = struct.unpack_from('<I', data, dir_offset + 4)[0]
    
    records_start = dir_offset + 8
    records_size = num_entries * 16
    names_start = records_start + records_size
    names_end = dir_end
    
    print(f"Файл: {bfs_path}")
    print(f"Размер: {file_size} байт")
    print(f"Записей: {num_entries}")
    
    # Парсинг записей (16 байт каждая)
    entries = []
    for i in range(num_entries):
        rec_off = records_start + i * 16
        rec = data[rec_off:rec_off + 16]
        f0 = struct.unpack_from('<H', rec, 0)[0]
        f1 = struct.unpack_from('<H', rec, 2)[0]
        f2 = struct.unpack_from('<H', rec, 4)[0]
        
        entry = {'index': i}
        
        if f1 == 0xFFFF:
            entry['kind'] = 'file'
            entry['offset'] = struct.unpack_from('<I', rec, 6)[0]
            entry['size'] = struct.unpack_from('<I', rec, 10)[0]
            entry['parent'] = struct.unpack_from('<H', rec, 14)[0]
            entry['valid'] = (8 <= entry['offset'] < file_size and 
                            0 < entry['size'] < file_size and 
                            entry['offset'] + entry['size'] <= file_size)
        else:
            entry['kind'] = 'folder'
            entry['parent'] = struct.unpack_from('<H', rec, 14)[0] if len(rec) > 14 else 0
        
        entries.append(entry)
    
    # Парсинг имён (null-terminated строки, идут подряд)
    names = []
    pos = names_start
    while pos < names_end:
        end = data.find(b'\x00', pos, names_end)
        if end < 0:
            break
        name_bytes = data[pos:end]
        if len(name_bytes) == 0:
            pos = end + 1
            continue
        try:
            name = name_bytes.decode('ascii')
            if all(32 <= b < 127 for b in name_bytes) and len(name) >= 1:
                names.append(name)
            else:
                names.append(None)
        except:
            names.append(None)
        pos = end + 1
    
    valid_names = [n for n in names if n is not None]
    print(f"Имён: {len(valid_names)} (валидных), {len(names) - len(valid_names)} пропущено")
    
    if len(valid_names) == num_entries:
        print(f">>> Имена ({len(valid_names)}) = записи ({num_entries}) — точное совпадение!")
    
    # Реконструкция путей через parent — только через папки
    def build_path(entry_idx):
        parts = []
        idx = entry_idx
        visited = set()
        while idx >= 0 and idx < num_entries and idx not in visited:
            visited.add(idx)
            name = valid_names[idx] if idx < len(valid_names) else None
            if name is None:
                break
            parts.append(name)
            # Если текущая запись — файл, не идём выше
            # (имя файла уже добавлено, путь готов)
            if entries[idx]['kind'] == 'file':
                break
            # Если папка — смотрим parent
            parent = entries[idx].get('parent', 0)
            if parent == 0 or parent == idx:
                break
            idx = parent
        
        parts.reverse()
        if len(parts) == 1:
            return parts[0]
        return os.path.join(*parts) if len(parts) > 1 else parts[0]
    
    # Извлечение
    os.makedirs(output_dir, exist_ok=True)
    extracted = 0
    errors = 0
    
    for i, entry in enumerate(entries):
        if entry['kind'] != 'file' or not entry.get('valid'):
            continue
        
        name = valid_names[i] if i < len(valid_names) else None
        if name is None:
            name = f"unknown_{i}.bin"
        
        off = entry['offset']
        sz = entry['size']
        
        # Деобфускация данных файла
        file_data = deobfuscate(data, off, sz)
        
        # Путь: имя файла + папки через parent
        # build_path для файла вернёт [папки...] / имя_файла
        try:
            rel_path = build_path(i)
        except:
            rel_path = name
        
        safe_path = rel_path.replace('\\', os.sep).replace('/', os.sep)
        out_path = os.path.join(output_dir, safe_path)
        out_subdir = os.path.dirname(out_path)
        if out_subdir and not os.path.exists(out_subdir):
            os.makedirs(out_subdir, exist_ok=True)
        
        try:
            with open(out_path, 'wb') as out:
                out.write(file_data)
            extracted += 1
            if extracted <= 20:
                sig = file_data[:4] if len(file_data) >= 4 else b''
                sig_str = ''
                if sig[:4] == b'RIFF':
                    sig_str = ' [WAV]'
                elif sig[:2] == b'\xff\xd8':
                    sig_str = ' [JPEG]'
                elif sig[:8] == b'\x89PNG\r\n\x1a\n':
                    sig_str = ' [PNG]'
                elif sig[:4] == b'OggS':
                    sig_str = ' [OGG]'
                elif sig[:2] == b'BM':
                    sig_str = ' [BMP]'
                elif sig[:3] == b'ID3' or sig[:2] == b'\xff\xfb':
                    sig_str = ' [MP3]'
                print(f"  {rel_path} ({sz} байт){sig_str}")
        except Exception as e:
            print(f"  ОШИБКА: {rel_path} — {e}")
            errors += 1
    
    print(f"\nИзвлечено: {extracted} файлов, ошибок: {errors}")
    print(f"Папка: {output_dir}/")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Использование: python uff_extract_v6.py <input.bfs> [output_dir]")
        sys.exit(1)
    bfs_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'extracted'
    extract_uff(bfs_path, output_dir)
