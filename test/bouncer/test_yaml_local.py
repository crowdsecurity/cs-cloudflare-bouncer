
def test_yaml_local(bouncer, cf_cfg_factory):
    cfg = cf_cfg_factory()

    with bouncer(cfg) as cf:
        cf.wait_for_lines_fnmatch([
            "*no API key nor certificate provided*",
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()

    config_local = {
        'crowdsec_lapi_key': 'not-used'
    }

    with bouncer(cfg, config_local=config_local) as cf:
        cf.wait_for_lines_fnmatch([
            "*Using API key auth*"
        ])
        cf.proc.wait(timeout=0.2)
        assert not cf.proc.is_running()
