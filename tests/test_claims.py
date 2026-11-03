from pathlib import Path

import pytest

from shadow_verify.claims import load_claims, load_claims_file
from shadow_verify.errors import ClaimsError
from shadow_verify.yaml_subset import load_yaml_subset

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "claims.example.yaml"


def test_example_claims_file_parses():
    claims, digest = load_claims_file(EXAMPLE)
    assert len(digest) == 64
    assert [item.id for item in claims] == ["logs-locked", "ssh-closed", "deploy-role"]
    assert claims[0].expected["block_public_policy"] is True
    assert claims[1].expected["ingress_forbidden"][1]["cidr"] == "::/0"
    assert claims[1].expected["ingress_forbidden"][0]["from_port"] == 22
    assert claims[2].expected["no_admin_star"] is True
    assert claims[0].agent_note
    assert claims[0].terraform_address == "aws_s3_bucket.logs"


def test_json_claims_round_trip():
    text = """
    {
      "version": 1,
      "claims": [
        {
          "id": "logs",
          "statement": "locked",
          "resource_type": "s3_bucket",
          "identifier": "logs",
          "agent_note": "the model says PASS",
          "expected": {"block_public_acls": true}
        }
      ]
    }
    """
    claims = load_claims(text, ".json")
    assert claims[0].agent_note == "the model says PASS"
    assert claims[0].expected == {"block_public_acls": True}


def test_unknown_resource_type_is_a_claims_error():
    text = """
    version: 1
    claims:
      - id: mystery
        statement: something
        resource_type: s3_bukcet
        identifier: logs
        expected:
          block_public_acls: true
    """
    with pytest.raises(ClaimsError, match="no checker"):
        load_claims(text, ".yaml")


def test_yaml_rejects_tabs_and_anchors():
    with pytest.raises(ClaimsError, match="tabs"):
        load_yaml_subset("version:\t1\n")
    with pytest.raises(ClaimsError, match="anchors"):
        load_yaml_subset("version: &a 1\n")


def test_yaml_rejects_duplicate_keys():
    with pytest.raises(ClaimsError, match="duplicate"):
        load_yaml_subset("version: 1\nversion: 2\n")


def test_comments_and_quoted_strings():
    loaded = load_yaml_subset(
        'statement: "port: 22"  # comment\nflag: true\nport: 22\n'
    )
    assert loaded == {"statement": "port: 22", "flag": True, "port": 22}
