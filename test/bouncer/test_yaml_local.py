
def test_yaml_local(bouncer, cf_cfg_factory):
    cfg = cf_cfg_factory()

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*config does not contain LAPI url*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()

    config_local = {
        'crowdsec_lapi_url': 'http://localhost:8080',
        'crowdsec_lapi_key': 'notused'
    }

    with bouncer(cfg, config_local=config_local) as cf:
        cf.wait_for_lines_fnmatch([
            "*connect: connection refused*",
            "*process terminated with error: crowdsec LAPI stream has stopped*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()
