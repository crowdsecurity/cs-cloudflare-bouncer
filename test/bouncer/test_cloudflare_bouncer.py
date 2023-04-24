import pytest


def test_no_api_key(crowdsec, bouncer, cf_cfg_factory):
    cfg = cf_cfg_factory()
    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*no API key nor certificate provided*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()

    cfg['crowdsec_lapi_key'] = ''

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*no API key nor certificate provided*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()


@pytest.mark.skip(reason="BASEURL message - to fix")
def test_no_lapi_url(bouncer, cf_cfg_factory):
    cfg = cf_cfg_factory()

    cfg['crowdsec_lapi_key'] = 'not-used'

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*could not parse configuration: api_url is required*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()

    cfg['crowdsec_lapi_url'] = ''

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*could not parse configuration: api_url is required*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()

# TODO: test without update frequency


def test_no_lapi(bouncer, cf_cfg_factory):
    cfg = cf_cfg_factory()
    cfg['crowdsec_lapi_key'] = 'not-used'
    cfg['crowdsec_lapi_url'] = 'http://localhost:8237'

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*LAPI can't be reached*"
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()
