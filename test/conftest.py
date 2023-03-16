"""
Full integration test with a real Crowdsec running in Docker
"""

import contextlib
import os
import pathlib

import pytest

SCRIPT_DIR = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent
cf_binary = PROJECT_ROOT.joinpath("crowdsec-cloudflare-bouncer")


# Create a lapi container, registers a bouncer
# and runs it with the updated config.
# - Returns context manager that yields a tuple of (bouncer, lapi)
@pytest.fixture(scope='session')
def bouncer_with_lapi(bouncer, crowdsec, cf_cfg_factory, api_key_factory, tmp_path_factory):
    @contextlib.contextmanager
    def closure(config_lapi=None, config_bouncer=None, api_key=None):
        if config_bouncer is None:
            config_bouncer = {}
        if config_lapi is None:
            config_lapi = {}
        # can be overridden by config_lapi + config_bouncer
        api_key = api_key_factory()
        env = {
            'BOUNCER_KEY_custom': api_key,
        }
        try:
            env.update(config_lapi)
            with crowdsec(environment=env) as lapi:
                lapi.wait_for_http(8080, '/health')
                port = lapi.probe.get_bound_port('8080')
                cfg = cf_cfg_factory()
                cfg.setdefault('crowdsec_config', {})
                cfg['crowdsec_lapi_url'] = f'http://localhost:{port}/'
                cfg['crowdsec_lapi_key'] = api_key
                cfg.update(config_bouncer)
                with bouncer(cf_binary, cfg) as cb:
                    yield cb, lapi
        finally:
            pass

    yield closure


_default_config = {
    'log_mode': 'stdout',
    'log_level': 'info',
    'crowdsec_update_frequency': '1s',
}


@pytest.fixture(scope='session')
def cf_cfg_factory():
    def closure(**kw):
        cfg = _default_config.copy()
        cfg |= kw
        return cfg | kw
    yield closure
