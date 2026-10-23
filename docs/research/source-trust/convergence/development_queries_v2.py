"""Durable development-only query costs, charged before callback dispatch."""

from collections import Counter
import json
import math
import os

from corruption_graph import canonical, digest
from platform_contract import fcntl, require_secure_io
from validate_intake import require


class QueryLedger:
    def __init__(self, path, task_universes, *, split="development"):
        require_secure_io(locking=True)
        require(split == "development", "holdout_adaptation_forbidden")
        require(bool(task_universes) and all(isinstance(k, str) and isinstance(v, list) and bool(v)
                    and len(v) == len(set(v)) and all(isinstance(x, str) for x in v)
                    for k, v in task_universes.items()), "query_task_universes")
        self.path, self.universes = path, {task: tuple(ids) for task, ids in task_universes.items()}
        self.header = {"event": "header", "scope": "development", "max_queries_per_task": 20,
                       "task_universes_sha256": digest(task_universes)}
        self.counts = Counter()
        self.previous, self.sequence = None, 0
        existed = path.exists()
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.stream = os.fdopen(fd, "r+", encoding="utf-8")
        try:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise ValueError("single_query_writer_required") from None
        try:
            self._restore(existed)
        except BaseException:
            self.stream.close()
            raise

    def _restore(self, existed):
        records = [json.loads(line) for line in self.stream.read().splitlines()]
        if records:
            completed, reserved = set(), set()
            for record in records:
                payload = {k: v for k, v in record.items() if k != "record_sha256"}
                require(record["record_sha256"] == digest(payload)
                        and record["previous_sha256"] == self.previous
                        and record["sequence"] == self.sequence + 1, "query_hash_chain")
                if self.sequence == 0:
                    require({k: record[k] for k in self.header} == self.header, "query_header_binding")
                if record["event"] == "reserved":
                    require(record["task_id"] in self.universes, "known_query_task")
                    self.counts[record["task_id"]] += 1
                    require(record["query"] == self.counts[record["task_id"]], "sequential_query_cost")
                    reserved.add((record["task_id"], record["query"]))
                elif record["event"] in ("scored", "failed"):
                    key = record["task_id"], record["query"]
                    require(key in reserved and key not in completed, "query_outcome_has_one_reservation")
                    completed.add(key)
                else:
                    require(record["event"] == "header" and self.sequence == 0, "query_event_order")
                self.previous, self.sequence = record["record_sha256"], record["sequence"]
            require(all(n <= 20 for n in self.counts.values()), "query_budget_in_history")
        else:
            require(not existed, "empty_existing_query_ledger")
            self._append(self.header)

    def _append(self, event):
        record = {**event, "sequence": self.sequence + 1, "previous_sha256": self.previous}
        record["record_sha256"] = digest(record)
        self.stream.write(canonical(record).decode() + "\n")
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.previous, self.sequence = record["record_sha256"], record["sequence"]

    def query(self, task_id, candidate_ids, callback, *, seed):
        require(type(seed) is int and seed in (17, 29, 43, 71, 101), "query_seed")
        require(task_id in self.universes and self.counts[task_id] < 20, "query_task_budget_exhausted")
        require(isinstance(candidate_ids, list) and len(candidate_ids) == len(set(candidate_ids))
                and set(candidate_ids) <= set(self.universes[task_id]), "query_candidate_ids")
        self.counts[task_id] += 1
        number = self.counts[task_id]
        self._append({"event": "reserved", "task_id": task_id, "query": number,
                      "seed": seed, "candidate_ids": candidate_ids})
        try:
            score = callback(tuple(candidate_ids))
            require(type(score) in (int, float) and math.isfinite(score), "finite_query_score")
        except Exception:
            # Includes failed callbacks. Crashes after reservation also retain the cost.
            self._append({"event": "failed", "task_id": task_id, "query": number})
            return None
        self._append({"event": "scored", "task_id": task_id, "query": number, "score": score})
        return score

    def close(self):
        self.stream.close()
