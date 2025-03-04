"""Integrate with OVH Dynamic DNS service."""
import asyncio
from datetime import timedelta
import logging

import aiohttp
import async_timeout
import voluptuous as vol

from homeassistant.const import (
    CONF_DOMAIN,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_SCAN_INTERVAL,
)

from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType

_LOGGER = logging.getLogger(__name__)

DOMAIN = "ovh"
CONF_OVH_API_ENDPOINT = "ovh_api_endpoint"
# Global dictionary to store current IPs of each domain
CURRENT_IPS = {}

DEFAULT_INTERVAL = timedelta(minutes=15)
DEFAULT_API_ENDPOINT = "www.ovh.com/nic/update"

TIMEOUT = 30

OVH_ERRORS = {
    "nohost": "Hostname supplied does not exist under specified account",
    "badauth": "Invalid username password combination",
    "badagent": "Client disabled",
    "!donator": "An update request was sent with a feature that is not available",
    "abuse": "Username is blocked due to abuse",
}

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_DOMAIN): cv.string,
                vol.Required(CONF_USERNAME): cv.string,
                vol.Required(CONF_PASSWORD): cv.string,
                vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_INTERVAL): vol.All(
                    cv.time_period, cv.positive_timedelta
                ),
                vol.Optional(CONF_OVH_API_ENDPOINT, default=DEFAULT_API_ENDPOINT): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Initialize the OVH component."""
    conf = config[DOMAIN]
    domains = conf.get(CONF_DOMAIN).strip()
    user = conf.get(CONF_USERNAME).strip()
    password = conf.get(CONF_PASSWORD).strip()
    interval = conf.get(CONF_SCAN_INTERVAL)
    api_endpoint = conf.get(CONF_OVH_API_ENDPOINT).strip()
    domains_list = domains.split(",")

    session = async_get_clientsession(hass)

    for domain in domains_list:
        result = await _update_ovh(session, api_endpoint, domain, user, password)
        if not result:
            return False

    async def update_domain_interval(now):
        """Update the OVH entry."""
        for domain in domains_list:
            await _update_ovh(session, api_endpoint, domain, user, password)

    async_track_time_interval(hass, update_domain_interval, interval)

    return True


async def _update_ovh(session, api_endpoint, domain, user, password):
    """Update OVH."""
    global CURRENT_IPS
    try:
        # Get the current IP address
        ip_response = await session.get("https://api.ipify.org")
        ip_address = await ip_response.text()

        # If the IP has not changed for this domain, exit.
        if domain in CURRENT_IPS and CURRENT_IPS[domain] == ip_address:
            _LOGGER.debug("IP not changed for domain %s: %s", domain, ip_address)
            return True

        # Update OVH
        url = f"https://{user}:{password}@{api_endpoint}?system=dyndns&hostname={domain}&myip={ip_address}"
        async with async_timeout.timeout(TIMEOUT):
            resp = await session.get(url)
            body = await resp.text()

            if body.startswith("good") or body.startswith("nochg"):
                CURRENT_IPS[domain] = ip_address
                _LOGGER.info("OVH update for the domain: %s", domain)
                return True

            _LOGGER.warning("OVH upgrade failed: %s => %s", domain, OVH_ERRORS[body.strip()])

    except aiohttp.ClientError:
        _LOGGER.warning("Unable to connect to the OVH API")

    except asyncio.TimeoutError:
        _LOGGER.warning("Timeout from the OVH API for the domain: %s", domain)

    return False
