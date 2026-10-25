import json

from opensource_atlas import cli
from opensource_atlas.github import GitHubAPIError


def sample_repository():
    return {
        "full_name": "octo/example",
        "html_url": "https://github.com/octo/example",
        "description": "Example project",
        "pushed_at": "2025-12-20T00:00:00Z",
        "stargazers_count": 10,
        "forks_count": 2,
        "license": {"spdx_id": "MIT"},
        "archived": False,
    }


def test_inspect_json_writes_valid_json_to_stdout(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch_repository", lambda _: sample_repository())

    exit_code = cli.main(["inspect", "octo/example", "--format", "json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["repository"]["name"] == "octo/example"
    assert "health" in report


def test_inspect_markdown_writes_report_to_file(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "fetch_repository", lambda _: sample_repository())
    output = tmp_path / "report.md"

    exit_code = cli.main(["inspect", "octo/example", "--format", "markdown", "--output", str(output)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.strip() == f"Report written to {output}"
    assert captured.err == ""
    report = output.read_text(encoding="utf-8")
    assert "# Repository Intelligence Report: octo/example" in report
    assert "## Score breakdown" in report


def test_inspect_reports_github_errors_to_stderr(monkeypatch, capsys):
    def fail_fetch(_):
        raise GitHubAPIError("Repository not found.")

    monkeypatch.setattr(cli, "fetch_repository", fail_fetch)

    exit_code = cli.main(["inspect", "octo/missing"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err.strip() == "atlas: error: Repository not found."


def test_inspect_rejects_invalid_repository_without_traceback(capsys):
    exit_code = cli.main(["inspect", "not-a-repository"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "atlas: error:" in captured.err
    assert "Traceback" not in captured.err
