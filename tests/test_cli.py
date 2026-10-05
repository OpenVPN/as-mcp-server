"""setup verifies before it stores, check reports without secrets.

serve runs the stdio server.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from as_mcp_server import cli, secrets
from as_mcp_server.client import AccessServerClient
from as_mcp_server.profiles import Profile, read_profiles, write_profile
from tests.conftest import LOGIN, MFAAUTH, Router, body_of, load_fixture

pytestmark = pytest.mark.usefixtures("clean_env")
SERVER_INFO = ("GET", "/api/server/info")


@pytest.fixture
def config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("OPENVPN_AS_CONFIG_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def answers(monkeypatch: pytest.MonkeyPatch):
    """Feed canned answers to input() and getpass().

    `seen` lists every prompt, `hidden` only those asked through getpass (typed
    without echo). Fails loudly on an unexpected prompt.
    """
    queue: list[str] = []
    prompts: list[str] = []
    hidden_prompts: list[str] = []

    def fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        if not queue:
            raise AssertionError(f"unexpected prompt: {prompt!r}")
        return queue.pop(0)

    def fake_getpass(prompt: str = "") -> str:
        hidden_prompts.append(prompt)
        return fake_input(prompt)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)

    class Answers:
        def feed(self, *values: str) -> None:
            queue.extend(values)

        seen = prompts
        hidden = hidden_prompts

    return Answers()


@pytest.fixture
def routed(monkeypatch: pytest.MonkeyPatch):
    """Make the CLI's client talk to a Router instead of the network."""

    def install(routes: dict) -> Router:
        router = Router(
            {
                LOGIN: load_fixture("login_ok"),
                SERVER_INFO: load_fixture("server_info"),
                **routes,
            }
        )
        monkeypatch.setattr(
            cli,
            "_new_client",
            lambda config: AccessServerClient(config, transport=router.transport()),
        )
        return router

    return install


def test_serve_is_the_default_and_runs_without_a_banner(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path
) -> None:
    calls: list[dict] = []

    class FakeServer:
        def run(self, **kwargs) -> None:
            calls.append(kwargs)

    monkeypatch.setattr(cli, "build", lambda settings: FakeServer())
    assert cli.main([]) == 0
    assert calls == [{"show_banner": False}]


def test_setup_verifies_then_stores_profile_and_password(
    config_dir: Path, memory_keyring, answers, routed, capsys
) -> None:
    router = routed({})
    answers.feed("https://vpn.example.com:943/", "openvpn", "correct-horse")
    assert cli.main(["setup"]) == 0
    out = capsys.readouterr().out
    assert (
        "Connected to Access Server 3.2.2 at https://vpn.example.com:943 as openvpn."
        in out
    )
    assert "password stored in the OS keyring" in out
    assert "claude mcp add openvpn-as -- uvx as-mcp-server" in out
    assert "gemini mcp add -s user openvpn-as uvx as-mcp-server" in out
    assert "as-mcp-server#agent-setup" in out
    assert read_profiles(config_dir) == {
        "default": Profile("https://vpn.example.com:943", "openvpn")
    }
    assert memory_keyring.store == {(secrets.SERVICE_NAME, "default"): "correct-horse"}
    assert "correct-horse" not in out
    assert answers.hidden == ["Password (input hidden): "]
    assert (
        str(router.requests[0].url)
        == "https://vpn.example.com:943/api/auth/login/userpassword"
    )


def test_setup_prompts_for_an_mfa_code_only_when_challenged(
    config_dir: Path, memory_keyring, answers, routed
) -> None:
    router = routed(
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("mfaauth_ok"),
        }
    )
    answers.feed("https://vpn.example.com:943", "mfa-admin", "pw", "123456")
    assert cli.main(["setup"]) == 0
    assert any("MFA code" in prompt for prompt in answers.seen)
    assert len(router.sent("POST", "/api/auth/login/mfaauth")) == 1
    assert memory_keyring.store[(secrets.SERVICE_NAME, "default")] == "pw"


def test_setup_stores_nothing_when_the_login_is_rejected(
    config_dir: Path, memory_keyring, answers, routed, capsys
) -> None:
    routed({LOGIN: load_fixture("login_bad_password_403")})
    answers.feed("https://vpn.example.com:943", "openvpn", "wrong")
    assert cli.main(["setup"]) == 1
    assert "rejected the login" in capsys.readouterr().err
    assert read_profiles(config_dir) == {} and memory_keyring.store == {}


def test_setup_takes_flags_and_env_password_without_prompting(
    config_dir: Path, memory_keyring, answers, routed, monkeypatch: pytest.MonkeyPatch
) -> None:
    routed({})
    monkeypatch.setenv("OPENVPN_AS_PASSWORD", "from-env")
    assert (
        cli.main(
            ["setup", "--url", "https://vpn.example.com:943", "--username", "openvpn"]
        )
        == 0
    )
    assert answers.seen == []
    assert memory_keyring.store[(secrets.SERVICE_NAME, "default")] == "from-env"


def test_setup_offers_existing_values_as_defaults(
    config_dir: Path, memory_keyring, answers, routed
) -> None:
    write_profile(
        config_dir, "default", Profile("https://old.example:943", "old-admin")
    )
    routed({})
    answers.feed("", "", "pw")  # accept both defaults
    assert cli.main(["setup"]) == 0
    assert read_profiles(config_dir)["default"] == Profile(
        "https://old.example:943", "old-admin"
    )
    assert (
        "[https://old.example:943]" in answers.seen[0]
        and "[old-admin]" in answers.seen[1]
    )


@pytest.mark.usefixtures("no_keyring")
def test_setup_without_a_keyring_keeps_the_profile_and_points_at_the_env_var(
    config_dir: Path, answers, routed, capsys
) -> None:
    routed({})
    answers.feed("https://vpn.example.com:943", "openvpn", "pw")
    assert cli.main(["setup"]) == 1
    err = capsys.readouterr().err
    assert "could NOT be stored" in err and "OPENVPN_AS_PASSWORD" in err
    assert read_profiles(config_dir)["default"].url == "https://vpn.example.com:943"


def test_setup_clear_removes_profile_and_keyring_entry(
    config_dir: Path, memory_keyring, capsys
) -> None:
    write_profile(
        config_dir, "default", Profile("https://vpn.example.com:943", "openvpn")
    )
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "pw"
    assert cli.main(["setup", "--clear"]) == 0
    assert "removed: yes" in capsys.readouterr().out
    assert read_profiles(config_dir) == {} and memory_keyring.store == {}
    assert cli.main(["setup", "--clear"]) == 0
    assert "nothing stored" in capsys.readouterr().out


def test_check_reports_url_user_server_and_sources(
    config_dir: Path, memory_keyring, routed, capsys
) -> None:
    write_profile(
        config_dir, "default", Profile("https://vpn.example.com:943", "openvpn")
    )
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "check-test-password"
    routed({})
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "URL:      https://vpn.example.com:943 (from profile)" in out
    assert "User:     openvpn (from profile); password from keyring" in out
    assert "TLS:      verified" in out
    assert "Server:   Access Server 3.2.2 (413ca39f) on Ubuntu 24.04.4 LTS" in out
    assert "MemoryKeyring" in out
    assert "check-test-password" not in out


def test_check_warns_about_old_servers_and_insecure_tls(
    config_dir: Path, routed, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    status, info = load_fixture("server_info")
    routed({SERVER_INFO: (status, {**info, "version": "3.0.2"})})
    for name, value in {
        "URL": "https://vpn.example.com:943",
        "USER": "openvpn",
        "PASSWORD": "pw",
        "INSECURE": "true",
    }.items():
        monkeypatch.setenv(f"OPENVPN_AS_{name}", value)
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "TLS:      DISABLED (OPENVPN_AS_INSECURE=true)" in out
    assert "WARNING: Access Server 3.0.2 is below the supported minimum 3.1" in out


@pytest.mark.usefixtures("no_keyring")
def test_check_fails_with_the_configuration_error_when_nothing_is_configured(
    config_dir: Path, capsys
) -> None:
    assert cli.main(["check"]) == 1
    assert "not configured" in capsys.readouterr().err


def test_check_reports_a_saml_bound_account_without_asking_for_a_code(
    config_dir: Path, memory_keyring, answers, routed, capsys
) -> None:
    write_profile(
        config_dir, "default", Profile("https://vpn.example.com:943", "samluser")
    )
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "pw"
    router = routed({LOGIN: load_fixture("login_saml_required_401")})
    assert cli.main(["check"]) == 1
    err = capsys.readouterr().err
    assert "requires web based SAML authentication" in err
    assert "as-mcp-server does not support" in err
    assert not any("MFA code" in prompt for prompt in answers.seen)
    assert router.sent("POST", "/api/auth/login/mfaauth") == []


def test_check_prompts_with_the_servers_own_challenge_text(
    config_dir: Path, memory_keyring, answers, routed
) -> None:
    write_profile(
        config_dir, "default", Profile("https://vpn.example.com:943", "radius-admin")
    )
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "pw"
    router = routed(
        {
            LOGIN: load_fixture("login_challenge_radius_401"),
            MFAAUTH: load_fixture("mfaauth_radius_ok"),
        }
    )
    answers.feed("4321")
    assert cli.main(["check"]) == 0
    assert answers.seen == ["Enter your PIN: "] and answers.hidden == []
    assert (
        body_of(router.sent("POST", "/api/auth/login/mfaauth")[0])["response"] == "4321"
    )
    assert len(router.sent(*LOGIN)) == 1


def test_check_hides_the_answer_when_the_server_says_so(
    config_dir: Path, memory_keyring, answers, routed
) -> None:
    write_profile(
        config_dir, "default", Profile("https://vpn.example.com:943", "radius-admin")
    )
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "pw"
    status, body = load_fixture("login_challenge_radius_401")
    routed(
        {
            LOGIN: (status, {**body, "echo": False, "challenge": "Enter your PIN:"}),
            MFAAUTH: load_fixture("mfaauth_radius_ok"),
        }
    )
    answers.feed("4321")
    assert cli.main(["check"]) == 0
    assert answers.hidden == ["Enter your PIN: "]


def test_check_hides_the_answer_when_the_server_sends_no_prompt(
    config_dir: Path, memory_keyring, answers, routed
) -> None:
    """Without a prompt nobody knows whether the answer is secret: hide it."""
    write_profile(
        config_dir, "default", Profile("https://vpn.example.com:943", "radius-admin")
    )
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "pw"
    status, body = load_fixture("login_challenge_radius_401")
    routed(
        {
            LOGIN: (status, {"challenge_context": body["challenge_context"]}),
            MFAAUTH: load_fixture("mfaauth_radius_ok"),
        }
    )
    answers.feed("4321")
    assert cli.main(["check"]) == 0
    assert answers.hidden == ["Second factor: "]
