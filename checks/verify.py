"""Самостоятельная проверка публичного состава и поведения NML-01."""

import argparse
import hashlib
import json
import os
import platform
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def integrity(root):
    manifest = json.loads((root / "MANIFEST.json").read_text())
    require(type(manifest) is dict and manifest, "Пустой манифест")
    for name, digest in manifest.items():
        p = Path(name)
        require(not p.is_absolute() and ".." not in p.parts, "Путь за пределами пакета")
        target = root / p
        require(
            target.is_file() and not target.is_symlink(), "Нет обычного файла: " + name
        )
        require(sha(target) == digest, "Изменён файл: " + name)
    return len(manifest)


def invoke(args, *, records=None, payload=b"", work):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(work),
        "TMPDIR": str(work),
        "NML_TRACE_CHILD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    child = subprocess.Popen(
        list(map(str, args)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        cwd=work,
        env=env,
    )
    try:
        if records is None:
            out, err = child.communicate(payload, timeout=20)
        else:
            chunks = []
            deadline = time.monotonic() + 20
            for record in records:
                child.stdin.write(json.dumps(record).encode() + b"\n")
                child.stdin.flush()
                line = b""
                while b"\n" not in line:
                    require(time.monotonic() < deadline, "Нет своевременного ответа")
                    if not select.select([child.stdout], [], [], 0.1)[0]:
                        continue
                    chunk = os.read(child.stdout.fileno(), 4096)
                    require(bool(chunk), "Процесс завершился до ответа")
                    line += chunk
                    require(len(line) <= 65536, "Слишком большой отчёт")
                require(
                    line.count(b"\n") == 1 and line.endswith(b"\n"),
                    "Ответ без нового входа",
                )
                chunks.append(line)
            child.stdin.close()
            child.stdin = None
            tail, err = child.communicate(timeout=5)
            require(not tail, "Лишний ответ после входа")
            out = b"".join(chunks)
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if child.stdin is not None and child.stdin.closed:
            child.stdin = None
        child.communicate()
        raise
    try:
        os.killpg(child.pid, 0)
    except ProcessLookupError:
        pass
    else:
        os.killpg(child.pid, signal.SIGKILL)
        raise ValueError("После проверки остался дочерний процесс")
    require(len(out) + len(err) <= 1024**2, "Превышен предел вывода")
    return {
        "exit_code": child.returncode,
        "stdout": out.decode(),
        "stderr": err.decode(),
        "pid": child.pid,
    }


def clean(result):
    require(
        result["exit_code"] == 0 and result["stderr"].strip() == "NML_CHILD_EXIT=0",
        "Нештатное завершение",
    )


def rejected(result):
    require(
        result["exit_code"] == 2
        and "Ошибка NML-01" in result["stderr"]
        and "Traceback" not in result["stderr"]
        and "PermissionError" not in result["stderr"],
        "Нечистый отказ",
    )
    require(
        result["stderr"]
        .strip()
        .endswith(
            ("NML_CHILD_EXIT=0", "NML_CHILD_EXIT=2", "NML_CHILD_EXIT=not_started")
        ),
        "Нет завершения ядра",
    )


def matches(actual, expected):
    require(type(actual) is dict, "Отчёт не является объектом")
    for key, value in expected.items():
        require(
            key in actual and type(actual[key]) is type(value) and actual[key] == value,
            "Расхождение поля: " + key,
        )


def load_inputs(root, name):
    return [
        json.loads(line)
        for line in (root / "inputs" / (name + ".jsonl")).read_text().splitlines()
    ]


def checkpoint(outputs, point):
    wanted = dict(point["expected"])
    relation = wanted.pop("same_domain_state_as_checkpoint", None)
    actual = outputs[point["after_step"]]
    matches(actual, wanted)
    for field in point.get("absent", []):
        require(field not in actual, "Лишнее поле: " + field)
    if "same_as_step" in point:
        require(actual == outputs[point["same_as_step"]], "Состояние не восстановлено")
    if relation:
        require(
            relation == "C12:3" and actual == outputs[3],
            "Восстановление изменило состояние",
        )


def negatives(root):
    baseline, normal = load_inputs(root, "C01")
    c02 = load_inputs(root, "C02")
    decision = c02[2]
    dump = lambda rs: ("\n".join(json.dumps(r) for r in rs) + "\n").encode()
    result = {
        "malformed_json": (b"{broken}\n", 0),
        "empty": (b"", 0),
        "duplicate_key": (b'{"type":"tick","type":"register"}\n', 0),
        "too_large": (b"x" * 65537 + b"\n", 0),
    }
    variants = {
        "missing_field": {k: v for k, v in normal.items() if k != "source"},
        "wrong_type": normal | {"value": True},
        "wrong_unit": normal | {"unit": "ppm"},
        "wrong_identity": normal | {"sample_id": "S-404"},
        "bad_timestamp": normal | {"received_at": "2026-10-01T25:00:00Z"},
        "future_measurement": normal | {"event_at": "2026-10-01T10:00:00Z"},
        "deadline_tie": normal | {"received_at": "2026-10-01T09:45:00Z"},
        "extra_field": normal | {"permission": "issued"},
    }
    result.update({k: (dump([baseline, v]), 1) for k, v in variants.items()})
    decisions = {
        "empty_reason": decision | {"reason": " "},
        "wrong_revision": decision | {"result_revision": 2},
        "wrong_rule": decision | {"rule_version": "R-2"},
        "unknown_action": decision | {"action": "approve_shipment"},
        "backwards_decision": decision | {"at": "2026-10-01T09:19:00Z"},
        "missing_recipient": {k: v for k, v in c02[3].items() if k != "recipient"},
    }
    result.update({k: (dump(c02[:2] + [v]), 2) for k, v in decisions.items()})
    result["decision_without_result"] = (dump([baseline, decision]), 1)
    result["duplicate_decision_id"] = (dump(c02[:3] + [decision]), 3)
    result["changed_duplicate"] = (
        dump(c02[:2] + [normal | {"received_at": "2026-10-01T09:21:00Z"}]),
        2,
    )
    definitions = json.loads((root / "checks/scenarios.json").read_text())
    for case in definitions.get("negative_cases", []):
        require(case["id"] not in result, "Повтор отказного случая")
        result[case["id"]] = (dump(case["records"]), case["allowed_reports"])
    return result


def run_suite(root, binary, program=None, execute=invoke, temporary_parent=None):
    program = program or root
    definitions = json.loads((root / "checks/scenarios.json").read_text())
    result = {
        "passed": False,
        "platform": platform.system() + " " + platform.machine(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "binary_sha256": sha(binary),
        "checks": [],
        "scenarios": [],
    }

    def check(name, condition=True):
        require(condition, name)
        result["checks"].append({"name": name, "passed": True})

    receipt = {"storage_mode", "storage_seq", "storage_acknowledged"}
    with tempfile.TemporaryDirectory(
        prefix="nml-public-check-", dir=temporary_parent
    ) as directory:
        work = Path(directory)
        args = [sys.executable, "-I", program / "nml01.py", "--binary", binary]

        def run(extra=(), records=None, payload=b""):
            return execute(
                args + list(extra), records=records, payload=payload, work=work
            )

        observed = {}
        for case in definitions["cases"]:
            db = work / (case["id"] + ".sqlite")
            all_records, outputs, processes = [], [], []
            for name in case["phases"]:
                records = load_inputs(root, name)
                execution = run(["--store", db], records=records)
                clean(execution)
                processes.append(execution["pid"])
                states = [json.loads(line) for line in execution["stdout"].splitlines()]
                require(len(states) == len(records), "Неполные ответы")
                outputs += states
                all_records += records
            require(len(processes) == len(set(processes)), "Не было нового процесса")
            seq = 0
            for record, state in zip(all_records, outputs):
                if record != {"type": "status"}:
                    seq += 1
                matches(
                    state,
                    {
                        "permission": "not_issued",
                        "storage_mode": "file",
                        "storage_acknowledged": True,
                        "storage_seq": seq,
                    },
                )
                require(
                    set(definitions["required_fields"]) <= set(state), "Неполный отчёт"
                )
            checkpoints = []
            for point in case["checkpoints"]:
                actual = outputs[point["after_step"]]
                checkpoint(outputs, point)
                check(case["id"] + ":" + str(point["after_step"]))
                checkpoints.append(
                    {"after_step": point["after_step"], "actual": actual}
                )
            history = run(["--store", db, "--history"])
            clean(history)
            pairs = [
                (i, o) for i, o in zip(all_records, outputs) if i != {"type": "status"}
            ]
            wanted_history = {
                "records": len(pairs),
                "history": [
                    {
                        "seq": n,
                        "input": i,
                        "report": {k: v for k, v in o.items() if k not in receipt},
                    }
                    for n, (i, o) in enumerate(pairs, 1)
                ],
            }
            check(
                "history_" + case["id"], json.loads(history["stdout"]) == wanted_history
            )
            result["scenarios"].append({"id": case["id"], "checkpoints": checkpoints})
            observed[case["id"]] = outputs
            for record, state in pairs:
                if (
                    record["type"] == "decision"
                    and record["role"] == "quality_responsible"
                ):
                    matches(
                        state,
                        {
                            "decision_id": record["decision_id"],
                            "decision_reason": record["reason"],
                            "decision_at": record["at"],
                            "decision_rule_version": record["rule_version"],
                            "decision_basis_revision": record["result_revision"],
                            "decision_role": record["role"],
                            "decision_action": record["action"],
                            "decision_recipient": record.get("recipient", ""),
                        },
                    )
        memory = run(records=load_inputs(root, "C01"))
        clean(memory)
        check(
            "memory_is_not_durable",
            all(
                json.loads(s)["storage_acknowledged"] is False
                and json.loads(s)["storage_mode"] == "memory"
                for s in memory["stdout"].splitlines()
            ),
        )
        deadline = run(
            records=load_inputs(root, "C01")[:1]
            + [
                {
                    "type": "read_report",
                    "at": "2026-10-01T09:45:00Z",
                    "role": "site_supervisor",
                }
            ]
        )
        clean(deadline)
        matches(
            json.loads(deadline["stdout"].splitlines()[-1]),
            {
                "quality": "unknown",
                "overdue": True,
                "delay_episodes": 1,
                "logical_exceptions": 1,
                "review": "open",
            },
        )
        check("read_at_deadline")
        for name, (payload, allowed) in negatives(root).items():
            db = work / ("invalid-" + name + ".sqlite")
            attempted = run(["--store", db], payload=payload)
            rejected(attempted)
            emitted = [json.loads(s) for s in attempted["stdout"].splitlines()]
            require(len(emitted) == allowed, "Отчёт после неверного входа")
            with sqlite3.connect("file:" + str(db) + "?mode=ro", uri=True) as conn:
                require(
                    conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
                    == allowed,
                    "Неверный вход сохранён",
                )
            if allowed:
                restored = run(["--store", db], records=[{"type": "status"}])
                clean(restored)
                require(
                    json.loads(restored["stdout"]) == emitted[-1],
                    "Отказ повредил прежнее состояние",
                )
            check("invalid_" + name)
        for label, case_id, index, change in (
            ("absence", "C03", 2, {"quality": "conforming"}),
            ("role", "C10", 3, {"accepted_decisions": 1}),
            ("duplicate", "C12", 5, {"logical_results": 2}),
            ("late_delay", "C04", 2, {"delay_episodes": 0}),
            ("late_status", "C04", 2, {"data_status": "received"}),
            ("late_role", "C04-FLOW", 4, {"accepted_decisions": 1}),
            ("late_restart", "C04-FLOW", 6, {"decision_id": "LOST"}),
            ("late_first_receipt", "C04-FLOW", 7, {"waiting_closed_at": "2026-10-01T09:55:00Z"}),
            ("timely_repeat", "C04-TIMELY-REPEAT", 3, {"data_status": "late_received"}),
        ):
            changed = [dict(s) for s in observed[case_id]]
            changed[index].update(change)
            case = next(c for c in definitions["cases"] if c["id"] == case_id)
            point = next(p for p in case["checkpoints"] if p["after_step"] == index)
            try:
                checkpoint(changed, point)
            except ValueError:
                check("mutation_" + label)
            else:
                raise ValueError("Проверяющий принял испорченный отчёт")
    result["passed"] = True
    result["control_checkpoints"] = sum(
        len(c["checkpoints"]) for c in result["scenarios"]
    )
    result["check_count"] = len(result["checks"])
    result["temporary_environment_removed"] = not work.exists()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--integrity-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        count = integrity(root)
        if args.integrity_only:
            result = {"passed": True, "manifest_files": count}
        else:
            binary = (args.binary or root / "target/release/nml01-core").resolve()
            result = run_suite(root, binary)
            result["manifest_files"] = count
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        ValueError,
        OSError,
        KeyError,
        sqlite3.Error,
        subprocess.TimeoutExpired,
    ) as error:
        print("Проверка не пройдена: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
