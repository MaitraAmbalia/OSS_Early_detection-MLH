from app.domain.versions import normalize_package_name, version_is_affected
from app.services.snowflake import SnowflakeRepository


def test_npm_semver_range() -> None:
    assert version_is_affected("npm", "4.17.20", ">=4.0.0, <4.17.21").vulnerable
    assert not version_is_affected("npm", "4.17.21", ">=4.0.0 <4.17.21").vulnerable


def test_python_pep440_range_and_name_normalization() -> None:
    assert version_is_affected("pip", "2.0.0", ">=1.0,<2.1").vulnerable
    assert normalize_package_name("pypi", "My_Package.Name") == "my-package-name"


def test_missing_version_is_not_claimed_vulnerable() -> None:
    result = version_is_affected("npm", None, "<2.0.0")
    assert not result.vulnerable
    assert result.reason == "missing_resolved_version"


def test_osv_events_become_comparator_ranges() -> None:
    ranges = SnowflakeRepository._osv_ranges(
        [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
            }
        ]
    )
    assert ranges == [("<1.2.3", "1.2.3")]
