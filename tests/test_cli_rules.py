from typer.testing import CliRunner

from amihacked.cli import app


def test_validate_rules_command_succeeds():
    result = CliRunner().invoke(app, ["validate-rules"])

    assert result.exit_code == 0
    assert "Rules loaded:" in result.output
