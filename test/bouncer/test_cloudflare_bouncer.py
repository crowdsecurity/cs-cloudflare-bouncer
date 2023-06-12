import pytest


def test_no_api_key(crowdsec, bouncer, cf_cfg_factory):
    cfg = cf_cfg_factory()
    cfg['crowdsec_lapi_url'] = 'http://localhost:8080'

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*config does not contain LAPI key or certificate*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()

    cfg['crowdsec_lapi_key'] = ''

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*config does not contain LAPI key or certificate*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()


def test_no_lapi_url(bouncer, cf_cfg_factory):
    cfg = cf_cfg_factory()

    cfg['crowdsec_lapi_key'] = 'not-used'

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*config does not contain LAPI url*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()

    cfg['crowdsec_lapi_url'] = ''

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*config does not contain LAPI url*",
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
            "*connect: connection refused*",
            "*process terminated with error: crowdsec LAPI stream has stopped*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()
