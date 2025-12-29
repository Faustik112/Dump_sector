import struct
import sys
from typing import List, Dict, Any


def parse_mbr_complete(data: bytes, filename: str) -> Dict[str, Any]:
    if len(data) != 512:
        return {"error": f"Некорректный размер MBR: {len(data)} байт (должно быть 512)"}

    result = {
        "filename": filename,
        "size": len(data),
        "sections": {}
    }

    boot_code = data[:446]
    result["sections"]["boot_code"] = {
        "offset": "0x000-0x1BD",
        "size": 446,
        "hex_preview": " ".join(f"{b:02X}" for b in boot_code[:32]),
        "contains_data": any(b != 0 for b in boot_code),
        "analysis": parse_boot_code(boot_code),
    }

    partition_table = data[446:510]
    result["sections"]["partition_table"] = {
        "offset": "0x1BE-0x1FD",
        "size": 64,
        "partitions": parse_partition_table(partition_table),
    }

    signature = data[510:512]
    result["sections"]["signature"] = {
        "offset": "0x1FE-0x1FF",
        "size": 2,
        "hex": f"0x{signature[0]:02X} 0x{signature[1]:02X}",
        "valid": signature == b"\x55\xAA",
        "analysis": parse_signature(signature),
    }

    result["hex_dump"] = create_hex_dump(data)
    return result


def parse_boot_code(boot_code: bytes) -> List[str]:
    analysis: List[str] = []

    is_empty = all(b == 0 for b in boot_code)
    if is_empty:
        analysis.append("Загрузочный код: ОТСУТСТВУЕТ (все байты равны 0)")
        analysis.append("Это означает, что MBR не содержит кода загрузчика")
        analysis.append("Возможные причины: чистый диск, поврежденный MBR")
    else:
        analysis.append("Загрузочный код: ПРИСУТСТВУЕТ")

        if boot_code[:5] == b"\xEB\x63\x90\x4D\x53":
            analysis.append("Обнаружен: Windows MBR (стандартный)")
        elif b"GRUB" in boot_code or b"grub" in boot_code:
            analysis.append("Обнаружен: GRUB загрузчик")
        elif b"LILO" in boot_code:
            analysis.append("Обнаружен: LILO загрузчик")

        strings = extract_strings(boot_code)
        if strings:
            analysis.append(f"Обнаружены строки: {', '.join(strings[:5])}")

    zero_bytes = sum(1 for b in boot_code if b == 0)
    analysis.append(f"Статистика: {zero_bytes}/446 нулевых байтов ({zero_bytes / 446 * 100:.1f}%)")
    return analysis


def parse_partition_table(table_data: bytes) -> List[Dict[str, Any]]:
    partitions: List[Dict[str, Any]] = []

    partition_types = {
        0x00: "Пусто",
        0x01: "FAT12",
        0x04: "FAT16 <32M",
        0x05: "Extended",
        0x06: "FAT16",
        0x07: "NTFS/exFAT/HPFS",
        0x0B: "FAT32",
        0x0C: "FAT32 (LBA)",
        0x0E: "FAT16 (LBA)",
        0x0F: "Extended (LBA)",
        0x82: "Linux swap",
        0x83: "Linux",
        0x85: "Linux extended",
        0x8E: "Linux LVM",
        0xFD: "Linux RAID",
        0xEF: "EFI System",
        0xEE: "GPT Protective",
        0xFF: "BBT",
    }

    for i in range(4):
        offset = i * 16
        entry = table_data[offset : offset + 16]

        partition: Dict[str, Any] = {
            "index": i + 1,
            "offset_hex": f"0x{446 + offset:03X}",
            "offset_dec": 446 + offset,
            "raw_hex": " ".join(f"{b:02X}" for b in entry),
        }

        if entry[0] == 0 and entry[4] == 0:
            partition["status"] = "Пустой"
            partition["analysis"] = ["Запись свободна"]
        else:
            try:
                bootable = entry[0]
                type_code = entry[4]
                lba_start = struct.unpack("<I", entry[8:12])[0]
                sectors = struct.unpack("<I", entry[12:16])[0]

                partition["status"] = "Заполнен"
                partition["bootable"] = bootable == 0x80
                partition["type_code"] = f"0x{type_code:02X}"
                partition["type_name"] = partition_types.get(type_code, "Неизвестный")
                partition["lba_start"] = lba_start
                partition["sectors"] = sectors
                partition["size_bytes"] = sectors * 512
                partition["size_mb"] = (sectors * 512) / (1024 * 1024)
                partition["size_gb"] = partition["size_mb"] / 1024

                analysis: List[str] = []
                analysis.append(f"Активен: {'ДА' if partition['bootable'] else 'нет'}")
                analysis.append(f"Тип: {partition['type_name']} ({partition['type_code']})")
                analysis.append(f"Начальный сектор: {lba_start}")
                analysis.append(f"Секторов: {sectors:,}")
                analysis.append(f"Размер: {partition['size_mb']:.2f} MB ({partition['size_gb']:.3f} GB)")

                partition["analysis"] = analysis
            except Exception as e:
                partition["status"] = "Ошибка"
                partition["analysis"] = [f"Ошибка разбора: {e}"]

        partitions.append(partition)
    return partitions


def parse_signature(signature: bytes) -> List[str]:
    analysis: List[str] = []
    b1, b2 = signature[0], signature[1]

    analysis.append(f"Байт 1 (0x1FE): 0x{b1:02X} = {b1:08b} бинарный")
    analysis.append(f"Байт 2 (0x1FF): 0x{b2:02X} = {b2:08b} бинарный")

    if b1 == 0x55 and b2 == 0xAA:
        analysis.append("СИГНАТУРА КОРРЕКТНА: 0x55 0xAA")
        analysis.append("BIOS распознает этот сектор как загрузочный")
    else:
        analysis.append("СИГНАТУРА НЕКОРРЕКТНА: ожидается 0x55 0xAA")
        if b1 != 0x55:
            analysis.append(f"Байт 1 должен быть 0x55, а не 0x{b1:02X}")
        if b2 != 0xAA:
            analysis.append(f"Байт 2 должен быть 0xAA, а не 0x{b2:02X}")

    return analysis


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    strings: List[str] = []
    current: List[str] = []

    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []

    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def create_hex_dump(data: bytes) -> List[Dict[str, Any]]:
    dump: List[Dict[str, Any]] = []

    for i in range(0, 512, 16):
        hex_bytes = " ".join(f"{b:02X}" for b in data[i : i + 16])
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i : i + 16])

        if i < 446:
            section = "Загрузочный код"
        elif i < 510:
            section = "Таблица разделов"
        else:
            section = "Сигнатура"

        dump.append({
            "offset": f"0x{i:03X}",
            "offset_dec": i,
            "hex": hex_bytes,
            "ascii": ascii_part,
            "section": section,
        })
    return dump


def print_mbr_analysis(result: Dict[str, Any]) -> None:
    print("=" * 70)
    print("ПОЛНЫЙ ПАРСИНГ MBR - ВСЕ 512 БАЙТ")
    print("=" * 70)

    print(f"\nФайл: {result['filename']}")
    print(f"Размер: {result['size']} байт")

    print("\n" + "=" * 70)
    print("1. ЗАГРУЗОЧНЫЙ КОД (446 байт, 0x000-0x1BD)")
    print("=" * 70)
    boot_info = result["sections"]["boot_code"]
    for line in boot_info["analysis"]:
        print(f"   {line}")
    print(f"   HEX-превью: {boot_info['hex_preview']}...")

    print("\n" + "=" * 70)
    print("2. ТАБЛИЦА РАЗДЕЛОВ (64 байта, 0x1BE-0x1FD)")
    print("=" * 70)
    partitions = result["sections"]["partition_table"]["partitions"]

    empty_count = sum(1 for p in partitions if p["status"] == "Пустой")
    active_count = sum(1 for p in partitions if p.get("bootable", False))

    print(f"   Статистика: {4 - empty_count}/4 заполненных, {active_count} активных")

    for partition in partitions:
        print(f"\n   РАЗДЕЛ {partition['index']} (смещение {partition['offset_hex']}):")
        print(f"      HEX: {partition['raw_hex']}")
        if "analysis" in partition:
            for line in partition["analysis"]:
                print(f"      {line}")

    print("\n" + "=" * 70)
    print("3. СИГНАТУРА MBR (2 байта, 0x1FE-0x1FF)")
    print("=" * 70)
    sig_info = result["sections"]["signature"]
    print(f"   HEX: {sig_info['hex']}")
    for line in sig_info["analysis"]:
        print(f"   {line}")

    print("\n" + "=" * 70)
    print("4. ПОЛНЫЙ HEX-ДАМП (все 512 байт)")
    print("=" * 70)
    print("   Смещение  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII")
    print("   " + "-" * 60)

    for i, line in enumerate(result["hex_dump"]):
        section_marker = ""
        if line["section"] == "Таблица разделов" and i % 4 == 0:
            section_marker = f" [Раздел {i // 4 - 27 + 1}]"
        elif line["section"] == "Сигнатура":
            section_marker = " [SIGNATURE]"
        print(f"   {line['offset']}  {line['hex']:<47}  {line['ascii']}{section_marker}")

    print("\n" + "=" * 70)
    print("5. ИТОГОВЫЙ АНАЛИЗ")
    print("=" * 70)

    issues: List[str] = []
    if not boot_info["contains_data"]:
        issues.append("Загрузочный код отсутствует")
    if empty_count == 4:
        issues.append("Таблица разделов пустая")
    if not sig_info["valid"]:
        issues.append("Сигнатура MBR некорректна")

    if not issues:
        print("   MBR имеет корректную структуру")
        print("   Все проверки пройдены успешно")
    else:
        print("   Обнаружены проблемы:")
        for issue in issues:
            print(f"      {issue}")

    print(f"\n   Структура MBR:")
    print("      Загрузочный код: 446 байт (87.1%)")
    print("      Таблица разделов: 64 байта (12.5%)")
    print("      Сигнатура: 2 байта (0.4%)")
    print("      Всего: 512 байт (100%)")


def run_on_file(filename: str) -> None:
    try:
        print(" Загрузка и анализ MBR...")
        with open(filename, "rb") as f:
            data = f.read(512)

        if len(data) != 512:
            print(f" Ошибка: файл должен быть 512 байт, а не {len(data)}")
            return

        result = parse_mbr_complete(data, filename)
        if "error" in result:
            print(result["error"])
            return

        print_mbr_analysis(result)

    except FileNotFoundError:
        print(f" Файл '{filename}' не найден!")
        print("   Проверьте путь и имя файла")
    except Exception as e:
        print(f" Ошибка при анализе: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 70)
    print(" Анализ завершен!")
    print("=" * 70)


def main() -> None:
    while True:
        if len(sys.argv) >= 2:
            filename = sys.argv[1].strip('"')
        else:
            filename = input("Введите путь к файлу дампа MBR (или 'exit' для выхода): ").strip().strip('"')
        
        if filename.lower() in ['exit', 'quit', 'выход']:
            print("Программа завершена.")
            break
        
        if not filename:
            print("Путь к файлу не указан. Попробуйте снова.")
            continue
        
        run_on_file(filename)


if __name__ == "__main__":
    main()
