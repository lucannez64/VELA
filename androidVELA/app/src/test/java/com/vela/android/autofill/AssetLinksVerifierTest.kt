package com.vela.android.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Reading `assetlinks.json`. The fingerprint check is the substance: a package
 * name is squattable, a signing key is not.
 */
class AssetLinksVerifierTest {

    private val ours = setOf(
        "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:80:6C:C7:41:41:73:F3:34:BE:12:2E:C6:07:12"
    )
    private val pkg = "com.example.app"

    private fun statement(
        relation: String = "delegate_permission/common.get_login_creds",
        namespace: String = "android_app",
        packageName: String = pkg,
        fingerprint: String = ours.first(),
    ) = """
        [{
          "relation": ["$relation"],
          "target": {
            "namespace": "$namespace",
            "package_name": "$packageName",
            "sha256_cert_fingerprints": ["$fingerprint"]
          }
        }]
    """.trimIndent()

    @Test
    fun `a matching statement grants login`() {
        assertTrue(AssetLinksVerifier.statementGrantsLogin(statement(), pkg, ours))
    }

    @Test
    fun `a different signing key is rejected`() {
        // The impostor case: same package name, re-signed by someone else.
        val other = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        assertFalse(AssetLinksVerifier.statementGrantsLogin(statement(fingerprint = other), pkg, ours))
    }

    @Test
    fun `a different package is rejected`() {
        assertFalse(
            AssetLinksVerifier.statementGrantsLogin(statement(packageName = "com.other.app"), pkg, ours)
        )
    }

    @Test
    fun `handle_all_urls alone does not grant credentials`() {
        // The common case: a site publishes asset links for deep links only.
        // That says nothing about who may receive its passwords.
        assertFalse(
            AssetLinksVerifier.statementGrantsLogin(
                statement(relation = "delegate_permission/common.handle_all_urls"), pkg, ours
            )
        )
    }

    @Test
    fun `a web namespace target is not an app grant`() {
        assertFalse(
            AssetLinksVerifier.statementGrantsLogin(statement(namespace = "web"), pkg, ours)
        )
    }

    @Test
    fun `fingerprint formatting differences do not matter`() {
        val lowercase = ours.first().lowercase()
        assertTrue(AssetLinksVerifier.statementGrantsLogin(statement(fingerprint = lowercase), pkg, ours))
        assertTrue(AssetLinksVerifier.statementGrantsLogin(statement(), pkg, setOf(lowercase)))
    }

    @Test
    fun `an unsigned or unknown app is never granted`() {
        assertFalse(AssetLinksVerifier.statementGrantsLogin(statement(), pkg, emptySet()))
    }

    @Test
    fun `malformed or empty documents are rejected, not crashed on`() {
        assertFalse(AssetLinksVerifier.statementGrantsLogin("", pkg, ours))
        assertFalse(AssetLinksVerifier.statementGrantsLogin("not json", pkg, ours))
        assertFalse(AssetLinksVerifier.statementGrantsLogin("{}", pkg, ours))
        assertFalse(AssetLinksVerifier.statementGrantsLogin("[]", pkg, ours))
        assertFalse(AssetLinksVerifier.statementGrantsLogin("[{}]", pkg, ours))
        assertFalse(
            AssetLinksVerifier.statementGrantsLogin(
                """[{"relation":["delegate_permission/common.get_login_creds"],"target":{}}]""", pkg, ours
            )
        )
        assertFalse(
            AssetLinksVerifier.statementGrantsLogin(
                """[{"relation":["delegate_permission/common.get_login_creds"],
                    "target":{"namespace":"android_app","package_name":"$pkg"}}]""",
                pkg, ours
            )
        )
    }

    @Test
    fun `the granting statement is found among others`() {
        val document = """
            [
              {"relation":["delegate_permission/common.handle_all_urls"],
               "target":{"namespace":"android_app","package_name":"$pkg",
                         "sha256_cert_fingerprints":["${ours.first()}"]}},
              {"relation":["delegate_permission/common.get_login_creds"],
               "target":{"namespace":"android_app","package_name":"$pkg",
                         "sha256_cert_fingerprints":["${ours.first()}"]}}
            ]
        """.trimIndent()
        assertTrue(AssetLinksVerifier.statementGrantsLogin(document, pkg, ours))
    }
}
