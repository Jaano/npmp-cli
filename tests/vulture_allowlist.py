from npmp_cli import cli as _cli
from npmp_cli import cli_access_lists as _cli_access_lists
from npmp_cli import cli_certificates as _cli_certificates
from npmp_cli import cli_dead_hosts as _cli_dead_hosts
from npmp_cli import cli_proxy_hosts as _cli_proxy_hosts
from npmp_cli import cli_redirect_hosts as _cli_redirect_hosts
from npmp_cli import cli_settings as _cli_settings
from npmp_cli import cli_streams as _cli_streams
from npmp_cli.docker.specs import DockerDeadHostSpec, DockerProxyHostSpec, DockerRedirectionHostSpec, DockerStreamSpec
from npmp_cli.npmplus_api import NPMplusApi

_ = _cli._main
_ = _cli.save
_ = _cli.audit_log
_ = _cli.schema
_ = _cli.load
_ = _cli.sync_docker
_ = _cli.json_to_compose

_ = _cli_proxy_hosts.proxy_host_list
_ = _cli_proxy_hosts.proxy_host_show
_ = _cli_proxy_hosts.proxy_host_create
_ = _cli_proxy_hosts.proxy_host_update
_ = _cli_proxy_hosts.proxy_host_delete
_ = _cli_proxy_hosts.proxy_host_enable
_ = _cli_proxy_hosts.proxy_host_disable

_ = _cli_dead_hosts.dead_host_list
_ = _cli_dead_hosts.dead_host_show
_ = _cli_dead_hosts.dead_host_create
_ = _cli_dead_hosts.dead_host_update
_ = _cli_dead_hosts.dead_host_delete
_ = _cli_dead_hosts.dead_host_enable
_ = _cli_dead_hosts.dead_host_disable

_ = _cli_redirect_hosts.redirect_host_list
_ = _cli_redirect_hosts.redirect_host_show
_ = _cli_redirect_hosts.redirect_host_create
_ = _cli_redirect_hosts.redirect_host_update
_ = _cli_redirect_hosts.redirect_host_delete
_ = _cli_redirect_hosts.redirect_host_enable
_ = _cli_redirect_hosts.redirect_host_disable

_ = _cli_streams.stream_list
_ = _cli_streams.stream_show
_ = _cli_streams.stream_create
_ = _cli_streams.stream_update
_ = _cli_streams.stream_delete
_ = _cli_streams.stream_enable
_ = _cli_streams.stream_disable

_ = _cli_access_lists.access_list_list
_ = _cli_access_lists.access_list_show
_ = _cli_access_lists.access_list_create
_ = _cli_access_lists.access_list_update
_ = _cli_access_lists.access_list_delete

_ = _cli_certificates.certificate_list
_ = _cli_certificates.certificate_show
_ = _cli_certificates.certificate_delete

_ = _cli_settings.settings_list
_ = _cli_settings.settings_show

_ = NPMplusApi.set_token_cookie
_ = NPMplusApi.login
_ = NPMplusApi.refresh_token
_ = NPMplusApi.logout
_ = NPMplusApi.get_health
_ = NPMplusApi.get_schema

_ = NPMplusApi.list_users
_ = NPMplusApi.get_user
_ = NPMplusApi.create_user
_ = NPMplusApi.update_user
_ = NPMplusApi.delete_user
_ = NPMplusApi.delete_all_users_ci_only
_ = NPMplusApi.set_user_password
_ = NPMplusApi.set_user_permissions
_ = NPMplusApi.login_as_user

_ = NPMplusApi.list_audit_log
_ = NPMplusApi.get_audit_event

_ = NPMplusApi.get_hosts_report

_ = NPMplusApi.list_settings
_ = NPMplusApi.get_setting
_ = NPMplusApi.set_setting

_ = NPMplusApi.check_version

_ = NPMplusApi.list_proxy_hosts
_ = NPMplusApi.get_proxy_host
_ = NPMplusApi.create_proxy_host
_ = NPMplusApi.update_proxy_host
_ = NPMplusApi.delete_proxy_host
_ = NPMplusApi.enable_proxy_host
_ = NPMplusApi.disable_proxy_host

_ = NPMplusApi.list_redirection_hosts
_ = NPMplusApi.get_redirection_host
_ = NPMplusApi.create_redirection_host
_ = NPMplusApi.update_redirection_host
_ = NPMplusApi.delete_redirection_host
_ = NPMplusApi.enable_redirection_host
_ = NPMplusApi.disable_redirection_host

_ = NPMplusApi.list_dead_hosts
_ = NPMplusApi.get_dead_host
_ = NPMplusApi.create_dead_host
_ = NPMplusApi.update_dead_host
_ = NPMplusApi.delete_dead_host
_ = NPMplusApi.enable_dead_host
_ = NPMplusApi.disable_dead_host

_ = NPMplusApi.list_streams
_ = NPMplusApi.get_stream
_ = NPMplusApi.create_stream
_ = NPMplusApi.update_stream
_ = NPMplusApi.delete_stream
_ = NPMplusApi.enable_stream
_ = NPMplusApi.disable_stream

_ = NPMplusApi.list_access_lists
_ = NPMplusApi.get_access_list
_ = NPMplusApi.create_access_list
_ = NPMplusApi.update_access_list
_ = NPMplusApi.delete_access_list

_ = NPMplusApi.list_certificates
_ = NPMplusApi.get_certificate
_ = NPMplusApi.create_certificate
_ = NPMplusApi.delete_certificate
_ = NPMplusApi.list_certificate_dns_providers
_ = NPMplusApi.test_certificate_http_challenge
_ = NPMplusApi.validate_certificate_files
_ = NPMplusApi.upload_certificate_files
_ = NPMplusApi.renew_certificate
_ = NPMplusApi.download_certificate

# Dataclass fields that vulture cannot detect
_ = DockerProxyHostSpec.hsts_enabled
_ = DockerProxyHostSpec.hsts_subdomains
_ = DockerProxyHostSpec.http2_support
_ = DockerProxyHostSpec.ssl_forced
_ = DockerDeadHostSpec.ssl_forced
_ = DockerDeadHostSpec.hsts_enabled
_ = DockerDeadHostSpec.hsts_subdomains
_ = DockerDeadHostSpec.http2_support
_ = DockerRedirectionHostSpec.preserve_path
_ = DockerRedirectionHostSpec.ssl_forced
_ = DockerRedirectionHostSpec.hsts_enabled
_ = DockerRedirectionHostSpec.hsts_subdomains
_ = DockerRedirectionHostSpec.http2_support
_ = DockerStreamSpec.tcp_forwarding
_ = DockerStreamSpec.udp_forwarding
_ = DockerStreamSpec.proxy_protocol_forwarding
