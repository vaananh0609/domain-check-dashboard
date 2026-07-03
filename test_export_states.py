from web_app import (
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
    STATUS_TIMEOUT,
    _export_df_for_entry,
    _export_state_slug,
    _export_status_series,
    _parse_export_states,
    _subset_export_columns,
)
from web_app import _df_from_store


def test_parse_export_states_all():
    assert _parse_export_states("ALL") is None
    assert _parse_export_states("") is None
    assert _parse_export_states(
        f"{STATUS_BLOCKED},{STATUS_LEAKED},{STATUS_DEAD},{STATUS_TIMEOUT}"
    ) is None


def test_parse_export_states_subset():
    assert _parse_export_states(STATUS_LEAKED) == [STATUS_LEAKED]
    assert set(_parse_export_states(f"{STATUS_BLOCKED},{STATUS_TIMEOUT}") or []) == {
        STATUS_BLOCKED,
        STATUS_TIMEOUT,
    }


def test_export_state_slug_multi():
    assert _export_state_slug("ALL") == ""
    assert _export_state_slug(f"{STATUS_BLOCKED},{STATUS_LEAKED}") == "blocked_leaked_"
    assert _export_state_slug(STATUS_TIMEOUT) == "timeout_"


def test_export_status_from_status_column_legacy_csv():
    old = (
        "STT,Domain,Local DNS,Public DNS,Status,HTTP\n"
        "1,a.com,x,y,Leaked,200\n"
        "2,b.com,x,y,Blocked,\n"
    )
    df = _df_from_store({"df_csv": old})
    status = _export_status_series(df)
    assert status.tolist() == [STATUS_LEAKED, STATUS_BLOCKED]


def test_export_df_legacy_csv_by_state():
    old = (
        "STT,Domain,Local DNS,Public DNS,Status,HTTP\n"
        "1,a.com,x,y,Leaked,200\n"
        "2,b.com,x,y,Blocked,\n"
    )
    entry = {"df_csv": old, "upload_stem": "old"}
    assert len(_export_df_for_entry(entry, None)) == 2
    leaked = _export_df_for_entry(entry, [STATUS_LEAKED])
    assert len(leaked) == 1
    assert leaked.iloc[0]["Domain"] == "a.com"


def test_export_subset_keeps_rows():
    old = (
        "STT,Domain,Status,HTTP\n"
        "1,a.com,Leaked,200\n"
    )
    entry = {"df_csv": old, "upload_stem": "x"}
    df = _export_df_for_entry(entry, None)
    out = _subset_export_columns(df, "stt,goc,ma_http,nguon_ket_luan")
    assert len(out) == 1
    assert "Domain" in out.columns
    assert "HTTP" in out.columns
