"""Exercise the checked-in Release workflow with only standard-library fakes.

No YAML dependency, gh command, network request, package build or service is
used. Exact step and heredoc boundaries locate the production Python; only its
function definitions are loaded, so publication code is never executed.
"""

import ast
import contextlib
import copy
import io
import json
from pathlib import Path
import re
import subprocess
import time
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"
REPOSITORY = "owner/phese"
COMMIT = "a" * 40
WORKFLOW_ID = 7
RUN_ID = 99
REQUIRED_STEPS = {
    "python": "Python standard library tests",
    "PHP 8.5.12 ZTS, FPM, Apache and bubblewrap":
        "Build pinned sources and run every supported-profile test",
}


def embedded_python(source, step_name):
    """Read one literal Python heredoc from an exact, uniquely named step.

    This deliberately understands the repository's narrow literal-block format,
    rather than claiming to parse YAML. Changed/missing/ambiguous delimiters
    fail the test instead of silently loading another step or skipping checks.
    """
    lines = source.splitlines()
    headers = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"( +)- name: (.+)", line)
        if match and match.group(2) == step_name:
            headers.append((index, len(match.group(1))))
    if len(headers) != 1:
        raise AssertionError("Expected exactly one workflow step: " + step_name)
    start, indentation = headers[0]
    stop = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and len(line) - len(line.lstrip()) <= indentation:
            stop = index
            break
    openings = []
    for index in range(start + 1, stop):
        match = re.fullmatch(r"( +)python3 - <<'PY'", lines[index])
        if match:
            openings.append((index, match.group(1)))
    if len(openings) != 1:
        raise AssertionError("Expected exactly one Python heredoc: " + step_name)
    opening, prefix = openings[0]
    body = []
    for line in lines[opening + 1:stop]:
        if line == prefix + "PY":
            return "\n".join(body) + "\n"
        if line and not line.startswith(prefix):
            raise AssertionError("Python heredoc indentation changed: " + step_name)
        body.append(line[len(prefix):] if line else "")
    raise AssertionError("Unterminated Python heredoc: " + step_name)


def forbid_external_call(*args, **kwargs):
    raise AssertionError("Release workflow test attempted an external command")


def workflow_functions(step_name):
    source = embedded_python(WORKFLOW.read_text(encoding="utf-8"), step_name)
    tree = ast.parse(source, filename=str(WORKFLOW))
    functions = [item for item in tree.body if isinstance(item, ast.FunctionDef)]
    if not functions:
        raise AssertionError("Expected workflow functions in " + step_name)
    namespace = {
        "time": time,
        "json": json,
        "re": re,
        "REPOSITORY": REPOSITORY,
        "HOST": "github.com",
        "subprocess": SimpleNamespace(run=forbid_external_call,
                                      check_output=forbid_external_call),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(WORKFLOW), "exec"), namespace)
    return namespace


def successful_run(**changes):
    run = {
        "id": RUN_ID, "head_sha": COMMIT, "workflow_id": WORKFLOW_ID,
        "event": "push", "name": "Checks", "path": ".github/workflows/ci.yml",
        "head_repository": {"full_name": REPOSITORY},
        "actor": {"login": "maintainer"}, "triggering_actor": {"login": "maintainer"},
        "run_attempt": 1, "status": "completed", "conclusion": "success",
    }
    run.update(changes)
    return run


def successful_jobs():
    return [{"name": name, "head_sha": COMMIT, "run_id": RUN_ID,
             "status": "completed", "conclusion": "success",
             "steps": [{"name": step, "conclusion": "success"}]}
            for name, step in REQUIRED_STEPS.items()]


class FakeClock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        if seconds <= 0:
            raise AssertionError("Expected a bounded positive polling interval")
        self.now += seconds


class ReleaseChecksGateTests(unittest.TestCase):
    def setUp(self):
        self.checks = workflow_functions("Require Checks for this commit")

    def run_gate(self, runs=None, jobs=None, detail=None, workflow_state="active", timeout=31):
        calls = []
        clock = FakeClock()

        def api(path):
            calls.append(path)
            if path == f"repos/{REPOSITORY}/actions/workflows/ci.yml":
                return [{"id": WORKFLOW_ID, "path": ".github/workflows/ci.yml", "state": workflow_state}]
            if path == f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs?head_sha={COMMIT}&event=push&per_page=100":
                return [{"workflow_runs": copy.deepcopy([successful_run()] if runs is None else runs)}]
            if path == f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/1/jobs?per_page=100":
                return [{"jobs": copy.deepcopy(successful_jobs() if jobs is None else jobs)}]
            if path == f"repos/{REPOSITORY}/actions/runs/{RUN_ID}":
                return [copy.deepcopy(successful_run() if detail is None else detail)]
            self.fail("Unexpected API request: " + path)

        self.checks["api"] = api
        with contextlib.redirect_stdout(io.StringIO()):
            result = self.checks["wait_for_checks"](
                COMMIT, timeout=timeout, clock=clock.monotonic, sleep=clock.sleep)
        return result, calls

    def test_success_requires_both_jobs_and_exact_attempt(self):
        run_id, calls = self.run_gate()
        self.assertEqual(run_id, RUN_ID)
        self.assertTrue(any("/attempts/1/jobs?" in path for path in calls))

    def test_ineligible_runs_are_ignored(self):
        changes = [
            {"head_sha": "b" * 40}, {"workflow_id": 8}, {"event": "pull_request"},
            {"name": "Other"}, {"path": ".github/workflows/other.yml"},
            {"head_repository": {"full_name": "fork/phese"}},
            {"actor": {"login": "dependabot[bot]"}},
            {"triggering_actor": {"login": "dependabot[bot]"}},
        ]
        for change in changes:
            with self.subTest(change=change):
                bad = successful_run(id=100, **change)
                # Include multiple API pages so filtering is not page-dependent.
                pages = [{"workflow_runs": [bad]}, {"workflow_runs": [successful_run()]}]
                chosen = self.checks["choose_run"](pages, COMMIT, WORKFLOW_ID)
                self.assertEqual(chosen["id"], RUN_ID)

    def test_failed_latest_run_cannot_fall_back_to_old_success(self):
        for conclusion in ("failure", "cancelled", "timed_out", "skipped", "neutral", "action_required"):
            with self.subTest(conclusion=conclusion):
                with self.assertRaisesRegex(RuntimeError, "Latest eligible Checks run failed"):
                    self.run_gate(runs=[successful_run(), successful_run(id=100, conclusion=conclusion)])

    def test_missing_or_queued_run_times_out(self):
        for runs in ([], [successful_run(status="queued", conclusion=None)]):
            with self.subTest(runs=runs), self.assertRaisesRegex(RuntimeError, "Timed out"):
                self.run_gate(runs=runs, timeout=16)

    def test_polling_can_observe_completion(self):
        clock = FakeClock()

        def api(path):
            if path.endswith("/ci.yml"):
                return [{"id": WORKFLOW_ID, "path": ".github/workflows/ci.yml", "state": "active"}]
            if "/ci.yml/runs?" in path:
                run = successful_run(status="in_progress", conclusion=None) if clock.now == 0 else successful_run()
                return [{"workflow_runs": [run]}]
            if "/jobs?" in path:
                return [{"jobs": successful_jobs()}]
            self.assertEqual(path, f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")
            return [successful_run()]

        self.checks["api"] = api
        with contextlib.redirect_stdout(io.StringIO()):
            result = self.checks["wait_for_checks"](
                COMMIT, timeout=31, clock=clock.monotonic, sleep=clock.sleep)
        self.assertEqual(result, RUN_ID)
        self.assertEqual(clock.now, 15)

    def test_disabled_workflow_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "missing or disabled"):
            self.run_gate(workflow_state="disabled_manually")

    def test_missing_duplicate_or_skipped_job_refuses(self):
        jobs = successful_jobs()
        cases = [jobs[:1], jobs + [jobs[0]], [jobs[0], dict(jobs[1], conclusion="skipped")]]
        for case in cases:
            with self.subTest(jobs=case), self.assertRaises(RuntimeError):
                self.run_gate(jobs=case)

    def test_wrong_job_commit_or_run_refuses(self):
        for change in ({"head_sha": "b" * 40}, {"run_id": 100}):
            jobs = successful_jobs()
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.run_gate(jobs=[dict(jobs[0], **change), jobs[1]])

    def test_native_real_test_step_must_succeed(self):
        jobs = successful_jobs()
        for steps in ([], [{"name": jobs[1]["steps"][0]["name"], "conclusion": "skipped"}]):
            with self.subTest(steps=steps), self.assertRaises(RuntimeError):
                self.run_gate(jobs=[jobs[0], dict(jobs[1], steps=steps)])

    def test_attempt_change_waits_and_reads_new_attempt(self):
        clock, paths = FakeClock(), []

        def api(path):
            paths.append(path)
            if path.endswith("/ci.yml"):
                return [{"id": WORKFLOW_ID, "path": ".github/workflows/ci.yml", "state": "active"}]
            if "/ci.yml/runs?" in path:
                return [{"workflow_runs": [successful_run(run_attempt=1 if clock.now == 0 else 2)]}]
            if "/jobs?" in path:
                self.assertRegex(path, rf"/runs/{RUN_ID}/attempts/[12]/jobs\?")
                return [{"jobs": successful_jobs()}]
            self.assertEqual(path, f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")
            return [successful_run(run_attempt=2)]

        self.checks["api"] = api
        with contextlib.redirect_stdout(io.StringIO()):
            result = self.checks["wait_for_checks"](
                COMMIT, timeout=31, clock=clock.monotonic, sleep=clock.sleep)
        self.assertEqual(result, RUN_ID)
        for attempt in (1, 2):
            self.assertTrue(any(f"/attempts/{attempt}/jobs?" in path for path in paths))

    def test_api_error_fails_closed(self):
        def api(path):
            raise subprocess.CalledProcessError(1, ["fake-gh", "api", path])

        self.checks["api"] = api
        with self.assertRaises(subprocess.CalledProcessError):
            self.checks["wait_for_checks"](COMMIT, timeout=1)


class ReleasePublicationGuardTests(unittest.TestCase):
    def setUp(self):
        self.publish = workflow_functions("Publish the verified tag once")
        self.publish.update(tag="v1.0.0", commit=COMMIT, repository=REPOSITORY, host="github.com")

    def fake_release_status(self, returncode, status):
        def run(command, **kwargs):
            self.assertEqual(command, ["gh", "api", "--hostname", "github.com", "--include",
                                       f"repos/{REPOSITORY}/releases/tags/v1.0.0"])
            return SimpleNamespace(returncode=returncode, stdout=status)

        self.publish["subprocess"] = SimpleNamespace(run=run, check_output=forbid_external_call)

    def test_existing_release_refuses(self):
        self.fake_release_status(0, "HTTP/2.0 200 OK\n")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.publish["require_absent_release"]()

    def test_only_explicit_404_means_absent(self):
        for status in ("HTTP/2.0 401 Unauthorized", "HTTP/2.0 403 Forbidden",
                       "HTTP/2.0 500 Internal Server Error", ""):
            self.fake_release_status(1, status)
            with self.subTest(status=status), self.assertRaisesRegex(RuntimeError, "Cannot establish"):
                self.publish["require_absent_release"]()
        self.fake_release_status(1, "HTTP/2.0 404 Not Found\n")
        self.publish["require_absent_release"]()

    def test_lightweight_and_annotated_tags_resolve(self):
        for annotated in (False, True):
            calls = []

            def api(path):
                calls.append(path)
                if path == f"repos/{REPOSITORY}/git/ref/tags/v1.0.0" and annotated:
                    return {"object": {"type": "tag", "sha": "b" * 40}}
                self.assertIn(path, [f"repos/{REPOSITORY}/git/ref/tags/v1.0.0",
                                     f"repos/{REPOSITORY}/git/tags/{'b' * 40}"])
                return {"object": {"type": "commit", "sha": COMMIT}}

            self.publish["api"] = api
            self.publish["require_remote_tag"]()
            self.assertEqual(len(calls), 2 if annotated else 1)

    def test_moved_or_unresolvable_tag_refuses(self):
        for obj in ({"type": "commit", "sha": "b" * 40},
                    {"type": "tree", "sha": COMMIT}, {"type": "tag", "sha": "invalid"}):
            self.publish["api"] = lambda path, obj=obj: {"object": obj}
            with self.subTest(obj=obj), self.assertRaises(RuntimeError):
                self.publish["require_remote_tag"]()

    def test_tag_cycle_is_bounded(self):
        calls = []

        def api(path):
            calls.append(path)
            return {"object": {"type": "tag", "sha": "b" * 40}}

        self.publish["api"] = api
        with self.assertRaisesRegex(RuntimeError, "Cannot resolve"):
            self.publish["require_remote_tag"]()
        self.assertEqual(len(calls), 9)


class ReleaseWorkflowStructureTests(unittest.TestCase):
    def test_inline_python_compiles_and_exact_delimiters_are_required(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        names = ("Select the existing release tag", "Require Checks for this commit",
                 "Publish the verified tag once")
        for name in names:
            with self.subTest(name=name):
                compile(embedded_python(source, name), str(WORKFLOW), "exec")
        name = names[-1]
        with self.assertRaisesRegex(AssertionError, "Unterminated"):
            embedded_python(source.rsplit("          PY", 1)[0], name)
        with self.assertRaisesRegex(AssertionError, "exactly one workflow step"):
            embedded_python(source + "\n      - name: " + name + "\n", name)

    def test_write_token_and_external_action_boundaries(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        verify, publish = source.split("\n  verify:\n", 1)[1].split("\n  publish:\n", 1)
        self.assertIn("    permissions:\n      contents: read\n      actions: read\n", verify)
        self.assertIn("    permissions:\n      contents: write\n", publish)
        self.assertEqual(len(re.findall(r"^      - name:", publish, re.MULTILINE)), 1)
        self.assertEqual(len(re.findall(r"^          GH_TOKEN:", publish, re.MULTILINE)), 1)
        self.assertIsNone(re.search(r"^\s*uses:", source, re.MULTILINE))


if __name__ == "__main__":
    unittest.main()
