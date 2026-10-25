"""JSON по одной записи на строку → ядро Rust; предметные оценки здесь не вычисляются."""

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

# Только соседний модуль поставки; не поиск кода в рабочем каталоге или HOME.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from storage import Store


def integer(value):
    if type(value) is not int or not -(2**63) <= value < 2**63:
        raise ValueError("Нужно целое число i64")
    return str(value)


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,64}", value):
        raise ValueError("Недопустимый идентификатор")
    return value


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value
    ):
        raise ValueError("Время должно быть YYYY-MM-DDTHH:MM:SSZ")
    moment = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    seconds = int(moment.timestamp())
    if seconds < 0:
        raise ValueError("Время до 1970 года не поддерживается")
    return str(seconds)


def fields(record, required):
    if type(record) is not dict or set(record) != set(required):
        raise ValueError("Состав полей записи не соответствует интерфейсу")


def encode(record):
    kind = record.get("type") if type(record) is dict else None
    if kind == "register":
        fields(
            record,
            [
                "type",
                "batch_id",
                "sample_id",
                "indicator",
                "sampled_at",
                "registered_at",
                "rule_version",
                "lower",
                "upper",
                "wait_minutes",
                "unit",
            ],
        )
        return "\t".join(
            [
                "init",
                identity(record["batch_id"]),
                identity(record["sample_id"]),
                identity(record["indicator"]),
                timestamp(record["sampled_at"]),
                timestamp(record["registered_at"]),
                identity(record["rule_version"]),
                integer(record["lower"]),
                integer(record["upper"]),
                integer(record["wait_minutes"]),
                identity(record["unit"]),
            ]
        )
    if kind == "tick":
        fields(record, ["type", "at"])
        return "tick\t" + timestamp(record["at"])
    if kind == "result":
        fields(
            record,
            [
                "type",
                "event_id",
                "source",
                "batch_id",
                "sample_id",
                "indicator",
                "revision",
                "event_at",
                "received_at",
                "value",
                "unit",
            ],
        )
        return "\t".join(
            [
                "result",
                identity(record["event_id"]),
                identity(record["source"]),
                identity(record["batch_id"]),
                identity(record["sample_id"]),
                identity(record["indicator"]),
                integer(record["revision"]),
                timestamp(record["event_at"]),
                timestamp(record["received_at"]),
                integer(record["value"]),
                identity(record["unit"]),
                record["event_at"],
                record["received_at"],
            ]
        )
    if kind == "read_report":
        fields(record, ["type", "at", "role"])
        return "\t".join(
            ["read_report", timestamp(record["at"]), identity(record["role"])]
        )
    if kind == "decision":
        required = [
            "type",
            "at",
            "decision_id",
            "role",
            "action",
            "reason",
            "rule_version",
            "result_revision",
        ]
        if record.get("action") == "escalate":
            required.append("recipient")
        fields(record, required)
        reason = record["reason"]
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason.encode()) > 2048
        ):
            raise ValueError("Нужно непустое основание до 2048 байт")
        return "\t".join(
            [
                "decision",
                identity(record["decision_id"]),
                identity(record["role"]),
                identity(record["action"]),
                reason.encode().hex(),
                identity(record["rule_version"]),
                integer(record["result_revision"]),
                timestamp(record["at"]),
                record["at"],
                identity(record["recipient"]) if "recipient" in record else "-",
            ]
        )
    raise ValueError("Неизвестный тип записи")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Повтор имени поля JSON")
        result[key] = value
    return result


class Core:
    def __init__(self, binary):
        self.child = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def send(self, wire):
        self.child.stdin.write(wire.encode() + b"\n")
        self.child.stdin.flush()
        output = self.child.stdout.readline(65537)
        if not output:
            raise ValueError(
                self.child.stderr.read(4096).decode().strip()
                or "Ядро не вернуло результат"
            )
        if len(output) > 65536:
            raise ValueError("Превышен предел отчёта")
        return json.loads(output)

    def close(self):
        try:
            if not self.child.stdin.closed:
                self.child.stdin.close()
            self.child.wait(timeout=2)
            return self.child.returncode
        finally:
            for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
                stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", type=Path, default=Path(__file__).parent / "bin/nml01-core"
    )
    parser.add_argument(
        "--store",
        type=Path,
        help="SQLite-файл истории; без параметра история только в памяти",
    )
    parser.add_argument(
        "--history", action="store_true", help="Экспорт ранее подтверждённой истории"
    )
    args = parser.parse_args()
    core = None
    store = None
    seen = False
    exit_code = 0
    try:
        if args.history and (args.store is None or not args.store.is_file()):
            raise ValueError("Для истории нужен существующий --store")
        store = Store(args.store, args.binary.resolve())
        core = Core(args.binary.resolve())
        last = None
        rows = store.rows()
        for seq, payload, wire, report in rows:
            if encode(json.loads(payload)) != wire:
                raise ValueError("Повреждена запись истории")
            last = core.send(wire)
            if last != json.loads(report):
                raise ValueError(
                    "Воспроизведение истории расходится с подтверждённым отчётом"
                )
        sequence = len(rows)
        if args.history:
            exported = [
                {"seq": seq, "input": json.loads(p), "report": json.loads(r)}
                for seq, p, w, r in rows
            ]
            text = json.dumps(
                {"history": exported, "records": len(rows)}, ensure_ascii=False
            )
            if len(text.encode()) > 1024 * 1024:
                raise ValueError("Экспорт превышает 1 MiB")
            print(text, flush=True)
            seen = True
        else:
            exit_code, seen = consume(core, store, last, sequence)
        if not seen:
            raise ValueError("Пустой вход")
    except (
        ValueError,
        OSError,
        RecursionError,
        OverflowError,
        sqlite3.Error,
        subprocess.TimeoutExpired,
    ) as error:
        print("Ошибка NML-01: " + str(error), file=sys.stderr)
        exit_code = 2
    finally:
        child_exit = "not_started"
        if core is not None:
            try:
                child_exit = core.close()
            except (OSError, subprocess.TimeoutExpired):
                print("Ошибка NML-01: ядро не завершилось после EOF", file=sys.stderr)
                exit_code = 3
            if exit_code == 0 and child_exit != 0:
                print("Ошибка NML-01: неуспешное завершение ядра", file=sys.stderr)
                exit_code = 2
        if store is not None:
            store.close()
        if os.environ.get("NML_TRACE_CHILD") == "1":
            print("NML_CHILD_EXIT=" + str(child_exit), file=sys.stderr)
    return exit_code


def consume(core, store, last, sequence):
    seen = False
    for count in range(1001):
        line = sys.stdin.buffer.readline(65537)
        if not line:
            break
        if len(line) > 65536 or count == 1000:
            raise ValueError("Превышен предел входа")
        record = json.loads(
            line,
            object_pairs_hook=unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("Не конечное число")
            ),
        )
        if record == {"type": "status"}:
            if last is None:
                raise ValueError("Нет подтверждённого состояния")
        else:
            wire = encode(record)
            last = core.send(wire)
            sequence = store.append(record, wire, last)
        print(
            json.dumps(
                last
                | {
                    "storage_seq": sequence,
                    "storage_mode": "file" if store.persistent else "memory",
                    "storage_acknowledged": store.persistent,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        seen = True
    return 0, seen


if __name__ == "__main__":
    raise SystemExit(main())
