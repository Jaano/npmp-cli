from npmp_cli import cli as _cli
from npmp_cli.npmplus_api import NPMplusApi

_ = _cli._main
_ = _cli.save
_ = _cli.schema
_ = _cli.load
_ = _cli.sync_docker
_ = _cli.json_to_compose

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
