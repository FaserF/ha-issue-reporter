"""Config flow for Issue Reporter."""

from __future__ import annotations

import asyncio
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .auth import (
    GitHubAuthError,
    async_poll_device_token,
    async_request_device_code,
    async_validate_github_app,
    async_validate_pat,
)
from .const import (
    AUTH_DEVICE_FLOW,
    AUTH_GITHUB_APP,
    AUTH_NONE,
    AUTH_PAT,
    CONF_APP_ID,
    CONF_AUTH_METHOD,
    CONF_CUSTOM_REDACTIONS,
    CONF_DRY_RUN,
    CONF_FALLBACK_AUTH_METHOD,
    CONF_FALLBACK_TOKEN,
    CONF_FALLBACK_USER,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
    CONF_INSTALLATION_ID,
    CONF_MIN_SEVERITY,
    CONF_OAUTH_CLIENT_ID,
    CONF_OWNER_ALLOWLIST,
    CONF_OWNER_FILTER_MODE,
    CONF_PRIVATE_KEY,
    DEFAULT_MIN_SEVERITY,
    DEFAULT_OAUTH_CLIENT_ID,
    DOMAIN,
    OWNER_FILTER_CUSTOM,
    OWNER_FILTER_MANUAL,
    OWNER_FILTER_SELF,
    SEVERITY_CRITICAL,
    SEVERITY_ERROR,
    SEVERITY_WARNING,
)
from .options_flow import IssueReporterOptionsFlow, split_csv_or_lines


class IssueReporterConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle initial setup and reauthentication for Issue Reporter."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize transient flow state."""
        self._data: dict[str, Any] = {}
        self._options: dict[str, Any] = {}
        self._device_info: dict[str, Any] = {}
        self._device_for_fallback: bool = False
        self._device_task: asyncio.Task[None] | None = None
        self._device_error: str | None = None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Create OptionsFlow handler."""
        return IssueReporterOptionsFlow()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Select primary GitHub authentication method."""
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()

        if user_input is not None:
            method = user_input[CONF_AUTH_METHOD]
            self._data[CONF_AUTH_METHOD] = method
            if method == AUTH_GITHUB_APP:
                return await self.async_step_auth_github_app()
            if method == AUTH_DEVICE_FLOW:
                self._device_for_fallback = False
                return await self.async_step_auth_device_flow()
            return await self.async_step_auth_pat()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_AUTH_METHOD, default=AUTH_GITHUB_APP
                    ): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SelectOptionDict(
                                    value=AUTH_GITHUB_APP,
                                    label="GitHub App / Bot (PEM)",
                                ),
                                SelectOptionDict(
                                    value=AUTH_DEVICE_FLOW,
                                    label="GitHub OAuth Device Flow",
                                ),
                                SelectOptionDict(
                                    value=AUTH_PAT, label="Personal Access Token (PAT)"
                                ),
                            ],
                            mode=SelectSelectorMode.LIST,
                        )
                    )
                }
            ),
        )

    async def async_step_auth_pat(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure Personal Access Token."""
        errors: dict[str, str] = {}
        if user_input is not None:
            token = user_input[CONF_GITHUB_TOKEN].strip()
            session = async_get_clientsession(self.hass)
            try:
                info = await async_validate_pat(session, token)
            except GitHubAuthError:
                errors["base"] = "invalid_auth"
            else:
                self._data[CONF_GITHUB_TOKEN] = token
                self._data[CONF_GITHUB_USER] = info.get("login", "")
                return await self.async_step_scope()

        return self.async_show_form(
            step_id="auth_pat",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_GITHUB_TOKEN): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    )
                }
            ),
            errors=errors,
        )

    async def async_step_auth_github_app(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure GitHub App credentials (e.g. faserf-hermes-agent[bot])."""
        errors: dict[str, str] = {}
        if user_input is not None:
            app_id = str(user_input[CONF_APP_ID]).strip()
            inst_id = str(user_input.get(CONF_INSTALLATION_ID) or "").strip()
            pem = str(user_input[CONF_PRIVATE_KEY]).strip()
            session = async_get_clientsession(self.hass)
            try:
                meta = await async_validate_github_app(
                    session, app_id, pem, inst_id or None
                )
            except GitHubAuthError:
                errors["base"] = "invalid_app_auth"
            else:
                self._data[CONF_APP_ID] = app_id
                self._data[CONF_INSTALLATION_ID] = meta["installation_id"]
                self._data[CONF_PRIVATE_KEY] = pem
                self._data[CONF_GITHUB_USER] = meta.get("account_login", "")
                return await self.async_step_fallback_auth()

        return self.async_show_form(
            step_id="auth_github_app",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_APP_ID): str,
                    vol.Optional(CONF_INSTALLATION_ID, default=""): str,
                    vol.Required(CONF_PRIVATE_KEY): TextSelector(
                        TextSelectorConfig(multiline=True)
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_auth_device_flow(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Start GitHub OAuth Device Flow."""
        errors: dict[str, str] = {}
        if user_input is not None:
            client_id = str(
                user_input.get(CONF_OAUTH_CLIENT_ID) or DEFAULT_OAUTH_CLIENT_ID
            ).strip()
            session = async_get_clientsession(self.hass)
            try:
                self._device_info = await async_request_device_code(session, client_id)
                self._data[CONF_OAUTH_CLIENT_ID] = client_id
            except GitHubAuthError:
                errors["base"] = "device_flow_error"
            else:
                self._device_task = None
                self._device_error = None
                return await self.async_step_device_flow_wait()

        return self.async_show_form(
            step_id="auth_device_flow",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_OAUTH_CLIENT_ID, default=DEFAULT_OAUTH_CLIENT_ID
                    ): str
                }
            ),
            errors=errors,
        )

    async def async_step_device_flow_wait(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Display Device Flow user code and wait for GitHub authorization."""
        if self._device_task is None:
            self._device_task = self.hass.async_create_task(
                self._async_run_device_poll()
            )

        if not self._device_task.done():
            return self.async_show_progress(
                step_id="device_flow_wait",
                progress_action="wait_device_flow",
                progress_task=self._device_task,
                description_placeholders={
                    "verification_uri": str(
                        self._device_info.get("verification_uri", "")
                    ),
                    "user_code": str(self._device_info.get("user_code", "")),
                },
            )

        if self._device_error:
            return self.async_show_progress_done(next_step_id="device_flow_failed")
        return self.async_show_progress_done(next_step_id="scope")

    async def _async_run_device_poll(self) -> None:
        """Background task polling GitHub OAuth token endpoint."""
        session = async_get_clientsession(self.hass)
        try:
            token = await async_poll_device_token(
                session,
                str(self._data.get(CONF_OAUTH_CLIENT_ID, "")),
                str(self._device_info.get("device_code", "")),
                interval=int(self._device_info.get("interval", 5)),
            )
            info = await async_validate_pat(session, token)
            if self._device_for_fallback:
                self._data[CONF_FALLBACK_AUTH_METHOD] = AUTH_DEVICE_FLOW
                self._data[CONF_FALLBACK_TOKEN] = token
                self._data[CONF_FALLBACK_USER] = info.get("login", "")
            else:
                self._data[CONF_GITHUB_TOKEN] = token
                self._data[CONF_GITHUB_USER] = info.get("login", "")
        except GitHubAuthError as err:
            self._device_error = str(err)

    async def async_step_device_flow_failed(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Abort when OAuth Device Flow authorization fails."""
        return self.async_abort(reason="device_flow_error")

    async def async_step_fallback_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Optional fallback user token when GitHub App is not installed on 3rd-party repos."""
        errors: dict[str, str] = {}
        if user_input is not None:
            fb_method = user_input[CONF_FALLBACK_AUTH_METHOD]
            fb_token = str(user_input.get(CONF_FALLBACK_TOKEN) or "").strip()
            self._data[CONF_FALLBACK_AUTH_METHOD] = fb_method
            if fb_method == AUTH_NONE:
                return await self.async_step_scope()
            if fb_method == AUTH_DEVICE_FLOW:
                self._device_for_fallback = True
                return await self.async_step_auth_device_flow()
            session = async_get_clientsession(self.hass)
            try:
                info = await async_validate_pat(session, fb_token)
            except GitHubAuthError:
                errors["base"] = "invalid_auth"
            else:
                self._data[CONF_FALLBACK_TOKEN] = fb_token
                self._data[CONF_FALLBACK_USER] = info.get("login", "")
                return await self.async_step_scope()

        return self.async_show_form(
            step_id="fallback_auth",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_FALLBACK_AUTH_METHOD, default=AUTH_NONE
                    ): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SelectOptionDict(
                                    value=AUTH_NONE,
                                    label="None (only repos with GitHub App installed)",
                                ),
                                SelectOptionDict(
                                    value=AUTH_PAT,
                                    label="Fallback Personal Access Token (PAT)",
                                ),
                                SelectOptionDict(
                                    value=AUTH_DEVICE_FLOW,
                                    label="Fallback GitHub OAuth Device Flow",
                                ),
                            ],
                            mode=SelectSelectorMode.LIST,
                        )
                    ),
                    vol.Optional(CONF_FALLBACK_TOKEN, default=""): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_scope(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure owner filter, severity, dry-run, and custom redactions."""
        owner = str(self._data.get(CONF_GITHUB_USER) or "your account")
        if user_input is not None and CONF_OWNER_FILTER_MODE in user_input:
            self._options = {
                CONF_OWNER_FILTER_MODE: user_input[CONF_OWNER_FILTER_MODE],
                CONF_OWNER_ALLOWLIST: split_csv_or_lines(
                    user_input.get(CONF_OWNER_ALLOWLIST)
                ),
                CONF_MIN_SEVERITY: user_input[CONF_MIN_SEVERITY],
                CONF_DRY_RUN: bool(user_input[CONF_DRY_RUN]),
                CONF_CUSTOM_REDACTIONS: split_csv_or_lines(
                    user_input.get(CONF_CUSTOM_REDACTIONS)
                ),
            }
            return self.async_create_entry(
                title=f"Issue Reporter ({owner})",
                data=self._data,
                options=self._options,
            )

        return self.async_show_form(
            step_id="scope",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_OWNER_FILTER_MODE, default=OWNER_FILTER_SELF
                    ): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SelectOptionDict(
                                    value=OWNER_FILTER_SELF,
                                    label=f"Only my repos ({owner})",
                                ),
                                SelectOptionDict(
                                    value=OWNER_FILTER_CUSTOM,
                                    label="Custom owner allowlist",
                                ),
                                SelectOptionDict(
                                    value=OWNER_FILTER_MANUAL,
                                    label="Manual opt-in per target",
                                ),
                            ],
                            mode=SelectSelectorMode.LIST,
                        )
                    ),
                    vol.Optional(CONF_OWNER_ALLOWLIST, default=""): str,
                    vol.Required(
                        CONF_MIN_SEVERITY, default=DEFAULT_MIN_SEVERITY
                    ): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SEVERITY_ERROR,
                                SEVERITY_WARNING,
                                SEVERITY_CRITICAL,
                            ],
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    vol.Required(CONF_DRY_RUN, default=True): bool,
                    vol.Optional(CONF_CUSTOM_REDACTIONS, default=""): str,
                }
            ),
            description_placeholders={"owner": owner},
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Handle reauthentication request when GitHub credentials fail."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-enter token or PEM credentials on reauthentication."""
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        method = entry.data.get(CONF_AUTH_METHOD, AUTH_PAT)
        session = async_get_clientsession(self.hass)

        if user_input is not None:
            updates = dict(entry.data)
            try:
                if method == AUTH_GITHUB_APP:
                    meta = await async_validate_github_app(
                        session,
                        str(entry.data.get(CONF_APP_ID, "")),
                        str(user_input[CONF_PRIVATE_KEY]),
                        entry.data.get(CONF_INSTALLATION_ID),
                    )
                    updates[CONF_PRIVATE_KEY] = str(
                        user_input[CONF_PRIVATE_KEY]
                    ).strip()
                    updates[CONF_INSTALLATION_ID] = meta["installation_id"]
                else:
                    token = str(user_input[CONF_GITHUB_TOKEN]).strip()
                    info = await async_validate_pat(session, token)
                    updates[CONF_GITHUB_TOKEN] = token
                    updates[CONF_GITHUB_USER] = info.get("login", "")
            except GitHubAuthError:
                errors["base"] = "invalid_auth"
            else:
                return self.async_update_reload_and_abort(entry, data=updates)

        schema = (
            vol.Schema(
                {
                    vol.Required(CONF_PRIVATE_KEY): TextSelector(
                        TextSelectorConfig(multiline=True)
                    )
                }
            )
            if method == AUTH_GITHUB_APP
            else vol.Schema(
                {
                    vol.Required(CONF_GITHUB_TOKEN): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    )
                }
            )
        )
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=schema, errors=errors
        )
