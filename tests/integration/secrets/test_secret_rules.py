from helpers import rule_ids

import oneleaks
from oneleaks import secret_rules


class TestBuiltinEntries:
    def test_loads_all_secret_rules(self):
        entries = secret_rules.builtin_entries()
        ids = {e["id"] for e in entries}
        assert {"aws-access-key-id", "github-pat", "openai-api-key"} <= ids

    def test_every_entry_is_secret_category(self):
        assert all(e["category"] == "secret" for e in secret_rules.builtin_entries())


# --- The rules find what they are meant to find ---


class TestProviderRules:
    def test_aws_access_key(self):
        result = oneleaks.scan("key = AKIAABCDEFGHIJKLMNOP")
        assert "aws-access-key-id" in rule_ids(result)

    def test_aws_access_key_negative(self):
        result = oneleaks.scan("key = AKIAABCDEFGHIJKLMNO")  # one char short
        assert "aws-access-key-id" not in rule_ids(result)

    def test_github_pat(self):
        result = oneleaks.scan("ghp_" + "a" * 36)
        assert "github-pat" in rule_ids(result)

    def test_github_pat_boundary_too_short(self):
        result = oneleaks.scan("ghp_" + "a" * 35)
        assert "github-pat" not in rule_ids(result)

    def test_openai_key(self):
        result = oneleaks.scan("sk-proj-" + "a" * 20)
        assert "openai-api-key" in rule_ids(result)

    def test_openai_key_legacy_with_keyword_context(self):
        result = oneleaks.scan("openai_api_key = sk-" + "a" * 20)
        assert "openai-api-key-legacy" in rule_ids(result)

    def test_openai_key_legacy_negative_without_keyword_context(self):
        result = oneleaks.scan("token = sk-" + "a" * 20)
        assert "openai-api-key-legacy" not in rule_ids(result)

    def test_openai_key_legacy_does_not_shadow_prefixed_form(self):
        # sk-proj-/sk-svcacct-/sk-ant- must never also match the legacy
        # bare-sk- rule, even with keyword context present.
        result = oneleaks.scan("openai_api_key = sk-proj-" + "a" * 20)
        assert "openai-api-key-legacy" not in rule_ids(result)
        assert "openai-api-key" in rule_ids(result)

    def test_anthropic_key(self):
        result = oneleaks.scan("sk-ant-" + "a" * 20)
        assert "anthropic-api-key" in rule_ids(result)

    def test_stripe_secret_key(self):
        result = oneleaks.scan("sk_live_" + "a" * 24)
        assert "stripe-secret-key" in rule_ids(result)

    def test_npm_token(self):
        result = oneleaks.scan("npm_" + "a" * 36)
        assert "npm-token" in rule_ids(result)

    def test_gitlab_pat(self):
        result = oneleaks.scan("glpat-" + "a" * 20)
        assert "gitlab-pat" in rule_ids(result)

    def test_gitlab_pat_boundary_too_short(self):
        result = oneleaks.scan("glpat-" + "a" * 19)
        assert "gitlab-pat" not in rule_ids(result)

    def test_slack_token(self):
        result = oneleaks.scan("xoxb-" + "a" * 10)
        assert "slack-token" in rule_ids(result)

    def test_slack_token_all_valid_prefixes(self):
        for prefix in "baprs":
            result = oneleaks.scan(f"xox{prefix}-" + "a" * 15)
            assert "slack-token" in rule_ids(result), f"prefix {prefix} should match"

    def test_slack_token_boundary_too_short(self):
        result = oneleaks.scan("xoxb-" + "a" * 9)
        assert "slack-token" not in rule_ids(result)

    def test_slack_webhook_url(self):
        # Assembled from parts on purpose. Written as one contiguous literal,
        # this fixture trips GitHub's push protection, which blocks the push
        # even though the value is obviously fake. Their webhook detector is
        # purely structural, so there is no "clearly a test value" it accepts.
        # A secret scanner's own fixtures have to dodge other secret scanners.
        # Do not "simplify" this back into a single string.
        host = "hooks.slack.com"
        url = f"https://{host}/services/T{'0' * 8}/B{'0' * 8}/{'X' * 24}"
        result = oneleaks.scan(url)
        assert "slack-webhook-url" in rule_ids(result)

    def test_slack_webhook_url_negative_wrong_domain(self):
        result = oneleaks.scan("https://not-slack.example.com/services/T00000000/B00000000/X")
        assert "slack-webhook-url" not in rule_ids(result)

    def test_twilio_api_key(self):
        result = oneleaks.scan("SK" + "a" * 32)
        assert "twilio-api-key" in rule_ids(result)

    def test_twilio_api_key_boundary_too_short(self):
        result = oneleaks.scan("SK" + "a" * 31)
        assert "twilio-api-key" not in rule_ids(result)

    def test_datadog_api_key_with_keyword_context(self):
        result = oneleaks.scan("datadog_api_key = " + "a" * 32)
        assert "datadog-api-key" in rule_ids(result)

    def test_datadog_api_key_negative_without_keyword_context(self):
        # Bare 32-char hex string with no "datadog"/"dd_api_key" nearby
        # should not fire. This rule requires keyword context precisely
        # because a bare 32-hex-char pattern is indistinguishable from an
        # MD5 hash otherwise.
        result = oneleaks.scan("checksum = " + "a" * 32)
        assert "datadog-api-key" not in rule_ids(result)

    def test_google_api_key(self):
        result = oneleaks.scan("AIza" + "a" * 35)
        assert "google-api-key" in rule_ids(result)

    def test_google_api_key_boundary_too_short(self):
        result = oneleaks.scan("AIza" + "a" * 34)
        assert "google-api-key" not in rule_ids(result)

    def test_pypi_token(self):
        result = oneleaks.scan("pypi-AgEIcHlwaS5vcmc" + "a" * 50)
        assert "pypi-token" in rule_ids(result)

    def test_pypi_token_boundary_too_short(self):
        result = oneleaks.scan("pypi-AgEIcHlwaS5vcmc" + "a" * 49)
        assert "pypi-token" not in rule_ids(result)

    def test_azure_storage_key(self):
        # Regression test: the original pattern's trailing \b could never be
        # satisfied after `==` padding (a non-word char), so this rule was
        # completely dead. Confirm it actually fires now.
        result = oneleaks.scan("AccountKey=" + "a" * 86 + "==;EndpointSuffix=core.windows.net")
        assert "azure-storage-key" in rule_ids(result)

    def test_aws_secret_access_key_span_does_not_shift_across_delimiter(self):
        # Regression test: the old bare-40-char-charset pattern could shift
        # left across the `=` delimiter (also a valid base64 char), capturing
        # part of "KEY=" instead of the real secret's last character.
        text = "AWS_SECRET_ACCESS_KEY=" + "a" * 39 + "/ next line here"
        result = oneleaks.scan(text)
        findings = [f for f in result.findings if f.rule_id == "aws-secret-access-key"]
        assert len(findings) == 1
        assert text[findings[0].start : findings[0].end] == "a" * 39 + "/"

    def test_openai_key_bounded_not_defeated_by_trailing_junk(self):
        # Regression test: a naive fix (bound the quantifier but keep a
        # trailing \b) makes this WORSE than the original bug: it goes
        # from "over-matches" to "matches nothing at all", since a bounded
        # quantifier can never backtrack to a valid \b position when the
        # word-character run continues past the cap. Must still detect the
        # key, bounded to a sane length rather than swallowing everything.
        text = "sk-proj-" + "a" * 20 + "X" * 500
        result = oneleaks.scan(text)
        findings = [f for f in result.findings if f.rule_id == "openai-api-key"]
        assert len(findings) == 1
        assert findings[0].end - findings[0].start < 150

    def test_ordinary_code_has_no_findings(self):
        result = oneleaks.scan("def add(a, b):\n    return a + b\n")
        assert result.safe

    def test_huggingface_token(self):
        result = oneleaks.scan("hf_" + "a" * 34)
        assert "huggingface-token" in rule_ids(result)

    def test_huggingface_token_boundary_too_short(self):
        result = oneleaks.scan("hf_" + "a" * 33)
        assert "huggingface-token" not in rule_ids(result)

    def test_replicate_api_token(self):
        result = oneleaks.scan("r8_" + "a" * 37)
        assert "replicate-api-token" in rule_ids(result)

    def test_replicate_api_token_boundary_too_short(self):
        result = oneleaks.scan("r8_" + "a" * 36)
        assert "replicate-api-token" not in rule_ids(result)

    def test_groq_api_key(self):
        result = oneleaks.scan("gsk_" + "a" * 20)
        assert "groq-api-key" in rule_ids(result)

    def test_groq_api_key_boundary_too_short(self):
        result = oneleaks.scan("gsk_" + "a" * 19)
        assert "groq-api-key" not in rule_ids(result)

    def test_aws_temp_access_key_id(self):
        result = oneleaks.scan("key = ASIA" + "A" * 16)
        assert "aws-temp-access-key-id" in rule_ids(result)

    def test_aws_temp_access_key_id_boundary_too_short(self):
        result = oneleaks.scan("key = ASIA" + "A" * 15)
        assert "aws-temp-access-key-id" not in rule_ids(result)

    def test_digitalocean_pat(self):
        result = oneleaks.scan("dop_v1_" + "a" * 64)
        assert "digitalocean-pat" in rule_ids(result)

    def test_digitalocean_pat_boundary_too_short(self):
        result = oneleaks.scan("dop_v1_" + "a" * 63)
        assert "digitalocean-pat" not in rule_ids(result)

    def test_cloudflare_api_token_with_keyword_context(self):
        result = oneleaks.scan("cloudflare_api_token = " + "a" * 40)
        assert "cloudflare-api-token" in rule_ids(result)

    def test_cloudflare_api_token_negative_without_keyword_context(self):
        result = oneleaks.scan("checksum = " + "a" * 40)
        assert "cloudflare-api-token" not in rule_ids(result)

    def test_vault_service_token(self):
        result = oneleaks.scan("hvs." + "a" * 24)
        assert "vault-service-token" in rule_ids(result)

    def test_vault_service_token_boundary_too_short(self):
        result = oneleaks.scan("hvs." + "a" * 23)
        assert "vault-service-token" not in rule_ids(result)

    def test_docker_hub_pat(self):
        result = oneleaks.scan("dckr_pat_" + "a" * 27)
        assert "docker-hub-pat" in rule_ids(result)

    def test_docker_hub_pat_boundary_too_short(self):
        result = oneleaks.scan("dckr_pat_" + "a" * 26)
        assert "docker-hub-pat" not in rule_ids(result)

    def test_sendgrid_api_key(self):
        result = oneleaks.scan("SG." + "a" * 20 + "." + "a" * 20)
        assert "sendgrid-api-key" in rule_ids(result)

    def test_sendgrid_api_key_negative_missing_second_segment(self):
        result = oneleaks.scan("SG." + "a" * 20)
        assert "sendgrid-api-key" not in rule_ids(result)

    def test_postman_api_key(self):
        result = oneleaks.scan("PMAK-" + "a" * 24 + "-" + "a" * 34)
        assert "postman-api-key" in rule_ids(result)

    def test_postman_api_key_boundary_wrong_length(self):
        result = oneleaks.scan("PMAK-" + "a" * 23 + "-" + "a" * 34)
        assert "postman-api-key" not in rule_ids(result)

    def test_sentry_auth_token(self):
        result = oneleaks.scan("sntrys_" + "a" * 40)
        assert "sentry-auth-token" in rule_ids(result)

    def test_sentry_auth_token_user_prefix(self):
        result = oneleaks.scan("sntryu_" + "a" * 40)
        assert "sentry-auth-token" in rule_ids(result)

    def test_sentry_auth_token_boundary_too_short(self):
        result = oneleaks.scan("sntrys_" + "a" * 39)
        assert "sentry-auth-token" not in rule_ids(result)

    def test_newrelic_api_key(self):
        result = oneleaks.scan("NRAK-" + "A" * 27)
        assert "newrelic-api-key" in rule_ids(result)

    def test_newrelic_api_key_boundary_too_short(self):
        result = oneleaks.scan("NRAK-" + "A" * 26)
        assert "newrelic-api-key" not in rule_ids(result)

    def test_planetscale_token(self):
        result = oneleaks.scan("pscale_tkn_" + "a" * 32)
        assert "planetscale-token" in rule_ids(result)

    def test_planetscale_token_boundary_too_short(self):
        result = oneleaks.scan("pscale_tkn_" + "a" * 31)
        assert "planetscale-token" not in rule_ids(result)

    def test_supabase_access_token(self):
        result = oneleaks.scan("sbp_" + "a" * 40)
        assert "supabase-access-token" in rule_ids(result)

    def test_supabase_access_token_boundary_too_short(self):
        result = oneleaks.scan("sbp_" + "a" * 39)
        assert "supabase-access-token" not in rule_ids(result)

    def test_shopify_access_token_all_valid_prefixes(self):
        for prefix in ("shpat", "shpss", "shpca"):
            result = oneleaks.scan(f"{prefix}_" + "a" * 32)
            assert "shopify-access-token" in rule_ids(result), f"prefix {prefix} should match"

    def test_shopify_access_token_boundary_too_short(self):
        result = oneleaks.scan("shpat_" + "a" * 31)
        assert "shopify-access-token" not in rule_ids(result)

    def test_discord_bot_token(self):
        result = oneleaks.scan("M" + "a" * 23 + "." + "a" * 6 + "." + "a" * 27)
        assert "discord-bot-token" in rule_ids(result)

    def test_discord_bot_token_n_prefix(self):
        result = oneleaks.scan("N" + "a" * 23 + "." + "a" * 6 + "." + "a" * 27)
        assert "discord-bot-token" in rule_ids(result)

    def test_discord_bot_token_negative_missing_segment(self):
        result = oneleaks.scan("M" + "a" * 23 + "." + "a" * 6)
        assert "discord-bot-token" not in rule_ids(result)

    def test_discord_webhook_url(self):
        url = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 20
        result = oneleaks.scan(url)
        assert "discord-webhook-url" in rule_ids(result)

    def test_discord_webhook_url_discordapp_domain(self):
        url = "https://discordapp.com/api/webhooks/123456789012345678/" + "a" * 20
        result = oneleaks.scan(url)
        assert "discord-webhook-url" in rule_ids(result)

    def test_discord_webhook_url_negative_wrong_domain(self):
        url = "https://not-discord.example.com/api/webhooks/123456789012345678/" + "a" * 20
        result = oneleaks.scan(url)
        assert "discord-webhook-url" not in rule_ids(result)

    def test_telegram_bot_token(self):
        result = oneleaks.scan("12345678:" + "a" * 35)
        assert "telegram-bot-token" in rule_ids(result)

    def test_telegram_bot_token_negative_id_too_short(self):
        result = oneleaks.scan("1234567:" + "a" * 35)
        assert "telegram-bot-token" not in rule_ids(result)

    def test_http_basic_auth_credential(self):
        text = "https://user:hunter2@example.com/path"
        result = oneleaks.scan(text)
        findings = [f for f in result.findings if f.rule_id == "http-basic-auth-credential"]
        assert len(findings) == 1
        assert text[findings[0].start : findings[0].end] == "hunter2"

    def test_http_basic_auth_credential_negative_no_credential(self):
        result = oneleaks.scan("https://example.com/path")
        assert "http-basic-auth-credential" not in rule_ids(result)

    def test_terraform_cloud_token(self):
        result = oneleaks.scan("a" * 14 + ".atlasv1." + "a" * 60)
        assert "terraform-cloud-token" in rule_ids(result)

    def test_terraform_cloud_token_boundary_prefix_too_short(self):
        result = oneleaks.scan("a" * 13 + ".atlasv1." + "a" * 60)
        assert "terraform-cloud-token" not in rule_ids(result)

    def test_google_oauth_client_secret(self):
        result = oneleaks.scan("GOCSPX-" + "a" * 20)
        assert "google-oauth-client-secret" in rule_ids(result)

    def test_google_oauth_client_secret_boundary_too_short(self):
        result = oneleaks.scan("GOCSPX-" + "a" * 19)
        assert "google-oauth-client-secret" not in rule_ids(result)

    def test_heroku_api_key_with_keyword_context(self):
        result = oneleaks.scan("heroku_api_key = 12345678-1234-1234-1234-123456789012")
        assert "heroku-api-key" in rule_ids(result)

    def test_heroku_api_key_negative_without_keyword_context(self):
        result = oneleaks.scan("id = 12345678-1234-1234-1234-123456789012")
        assert "heroku-api-key" not in rule_ids(result)

    def test_mailchimp_api_key(self):
        result = oneleaks.scan("a" * 32 + "-us1")
        assert "mailchimp-api-key" in rule_ids(result)

    def test_mailchimp_api_key_negative_non_us_suffix(self):
        result = oneleaks.scan("a" * 32 + "-eu1")
        assert "mailchimp-api-key" not in rule_ids(result)

    def test_square_access_token(self):
        result = oneleaks.scan("sq0atp-" + "a" * 22)
        assert "square-access-token" in rule_ids(result)

    def test_square_access_token_boundary_too_short(self):
        result = oneleaks.scan("sq0atp-" + "a" * 21)
        assert "square-access-token" not in rule_ids(result)

    def test_square_oauth_secret(self):
        result = oneleaks.scan("sq0csp-" + "a" * 43)
        assert "square-oauth-secret" in rule_ids(result)

    def test_square_oauth_secret_boundary_too_short(self):
        result = oneleaks.scan("sq0csp-" + "a" * 42)
        assert "square-oauth-secret" not in rule_ids(result)

    def test_stripe_webhook_secret(self):
        result = oneleaks.scan("whsec_" + "a" * 32)
        assert "stripe-webhook-secret" in rule_ids(result)

    def test_stripe_webhook_secret_boundary_too_short(self):
        result = oneleaks.scan("whsec_" + "a" * 31)
        assert "stripe-webhook-secret" not in rule_ids(result)

    def test_linear_api_key(self):
        result = oneleaks.scan("lin_api_" + "a" * 40)
        assert "linear-api-key" in rule_ids(result)

    def test_linear_api_key_boundary_too_short(self):
        result = oneleaks.scan("lin_api_" + "a" * 39)
        assert "linear-api-key" not in rule_ids(result)

    def test_notion_integration_token(self):
        result = oneleaks.scan("ntn_" + "a" * 40)
        assert "notion-integration-token" in rule_ids(result)

    def test_notion_integration_token_boundary_too_short(self):
        result = oneleaks.scan("ntn_" + "a" * 39)
        assert "notion-integration-token" not in rule_ids(result)

    def test_airtable_pat(self):
        result = oneleaks.scan("pat" + "a" * 14 + "." + "a" * 64)
        assert "airtable-pat" in rule_ids(result)

    def test_airtable_pat_boundary_too_short(self):
        result = oneleaks.scan("pat" + "a" * 13 + "." + "a" * 64)
        assert "airtable-pat" not in rule_ids(result)

    def test_mapbox_secret_token_with_keyword_context(self):
        result = oneleaks.scan("mapbox_token = " + "sk." + "a" * 60)
        assert "mapbox-secret-token" in rule_ids(result)

    def test_mapbox_secret_token_negative_without_keyword_context(self):
        result = oneleaks.scan("sk." + "a" * 60)
        assert "mapbox-secret-token" not in rule_ids(result)

    def test_mapbox_secret_token_boundary_too_short(self):
        result = oneleaks.scan("mapbox_token = " + "sk." + "a" * 59)
        assert "mapbox-secret-token" not in rule_ids(result)

    def test_algolia_admin_api_key_with_keyword_context(self):
        result = oneleaks.scan("algolia_api_key = " + "a" * 32)
        assert "algolia-admin-api-key" in rule_ids(result)

    def test_algolia_admin_api_key_negative_without_keyword_context(self):
        result = oneleaks.scan("checksum = " + "a" * 32)
        assert "algolia-admin-api-key" not in rule_ids(result)

    def test_facebook_access_token_with_keyword_context(self):
        result = oneleaks.scan("facebook_access_token = " + "EAA" + "a" * 20)
        assert "facebook-access-token" in rule_ids(result)

    def test_facebook_access_token_negative_without_keyword_context(self):
        result = oneleaks.scan("EAA" + "a" * 20)
        assert "facebook-access-token" not in rule_ids(result)

    def test_facebook_access_token_boundary_too_short(self):
        result = oneleaks.scan("facebook_access_token = " + "EAA" + "a" * 19)
        assert "facebook-access-token" not in rule_ids(result)


# Prefix and body are kept apart on purpose. Written as one literal, these
# fixtures trip GitHub's push protection, which blocks the push even though the
# value is fake. Same reason as the Slack webhook fixture above: a secret
# scanner's own fixtures have to dodge other secret scanners. Do not "simplify"
# these into single strings.
_STRIPE_BODY = "51OuEMLAlTWGaDypq4P5cuDHbuKeG"
_OPENAI_ADMIN_BODY = "OYh8ozcxZzb-vq8fTGSha75cs2j7KTUKzHUh0Yck83WSzdUtmXO"


class TestProviderFormatCoverage:
    """Regressions for formats that real providers issue but the patterns
    originally missed. Samples follow the shapes gitleaks validates against.
    """

    def test_stripe_live_and_prod_keys(self):
        assert "stripe-secret-key" in rule_ids(oneleaks.scan("sk_live_" + _STRIPE_BODY))
        assert "stripe-restricted-key" in rule_ids(oneleaks.scan("rk_prod_" + _STRIPE_BODY))

    def test_stripe_test_keys_are_found_but_ranked_lower(self):
        # Real credentials, but they reach no real money, so they sit below
        # the live keys rather than alongside them.
        for prefix in ("sk_test_", "rk_test_"):
            findings = oneleaks.scan(prefix + _STRIPE_BODY).findings
            assert [f.rule_id for f in findings] == ["stripe-test-key"]
            assert findings[0].severity == "medium"

    def test_openai_admin_key(self):
        assert rule_ids(oneleaks.scan("sk-admin-" + _OPENAI_ADMIN_BODY)) == ["openai-api-key"]

    def test_openai_legacy_rule_does_not_double_report_admin_keys(self):
        text = "sk-admin-" + _OPENAI_ADMIN_BODY
        assert "openai-api-key-legacy" not in rule_ids(oneleaks.scan(text))

    def test_heroku_key_in_either_case(self):
        for uuid in (
            "12345678-abcd-abcd-abcd-1234567890ab",
            "12345678-ABCD-ABCD-ABCD-1234567890AB",
        ):
            assert "heroku-api-key" in rule_ids(oneleaks.scan(f"heroku_api_key = {uuid}"))


class TestPGPPrivateKey:
    def test_detects_pgp_block(self):
        block = (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        result = oneleaks.scan(block)
        findings = [f for f in result.findings if f.rule_id == "pgp-private-key"]
        assert len(findings) == 1
        assert findings[0].preview == "<PRIVATE_KEY>"

    def test_does_not_double_fire_pem_private_key(self):
        block = (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        result = oneleaks.scan(block)
        assert "pem-private-key" not in rule_ids(result)


class TestPEMPrivateKey:
    def test_detects_pem_block(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
        result = oneleaks.scan(pem)
        findings = [f for f in result.findings if f.rule_id == "pem-private-key"]
        assert len(findings) == 1
        assert findings[0].preview == "<PRIVATE_KEY>"


class TestConnectionString:
    def test_matches_only_credential_portion(self):
        text = "postgres://user:hunter2@db.example.com/mydb"
        result = oneleaks.scan(text)
        findings = [f for f in result.findings if f.rule_id == "connection-string-credential"]
        assert len(findings) == 1
        f = findings[0]
        assert text[f.start : f.end] == "hunter2"
