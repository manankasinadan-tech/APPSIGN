package com.hephaistos.appsign.cli

import com.hephaistos.appsign.core.apk.ApkSignerEngine
import com.hephaistos.appsign.core.apk.ApkVerifierEngine
import com.hephaistos.appsign.core.ask.ApkOperationException
import com.hephaistos.appsign.core.ask.AskDecryptionException
import com.hephaistos.appsign.core.ask.AskFormatException
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.ask.AskKeyMismatchException
import com.hephaistos.appsign.core.ask.AskPasswordRequiredException
import com.hephaistos.appsign.core.model.ApkResignResult
import com.hephaistos.appsign.core.model.ApkVerificationReport
import com.hephaistos.appsign.core.model.AskMode
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.KeyAlgorithm
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.model.UnlockedKeyMaterial
import com.hephaistos.appsign.core.report.ReportFormatters
import java.io.File
import java.io.PrintStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.util.concurrent.Callable
import kotlin.system.exitProcess
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import picocli.CommandLine.ParentCommand

object ExitCodes {
  const val OK = 0
  const val VERIFICATION_FAILED = 1
  const val USAGE_ERROR = 2
  const val IO_ERROR = 3
  const val CRYPTO_ERROR = 4
}

@Command(
  name = "appsign",
  mixinStandardHelpOptions = true,
  version = ["APPSIGN CLI 1.0.0"],
  description = [
    "APPSIGN — Offline APK Verification, ASK Key Management & Batch Resigning Suite.",
    "Usable on Termux, Linux, macOS, and CI pipelines.",
  ],
  subcommands = [
    VerifyCommand::class,
    ResignCommand::class,
    KeyCommand::class,
  ],
)
class AppsignCommand : Callable<Int> {
  @Option(
    names = ["--lang"],
    description = ["Output language: en or fr (default: en)"],
    scope = CommandLine.ScopeType.INHERIT,
  )
  var lang: String = "en"

  val isFrench: Boolean
    get() = lang.equals("fr", ignoreCase = true)

  override fun call(): Int {
    CommandLine(this).usage(System.out)
    return ExitCodes.OK
  }
}

@Command(
  name = "verify",
  mixinStandardHelpOptions = true,
  description = ["Verify APK v1, v2, v3, v3.1 and v4 signatures and inspect certificates."],
)
class VerifyCommand : Callable<Int> {
  @ParentCommand lateinit var root: AppsignCommand

  @Parameters(
    arity = "1..*",
    paramLabel = "<apk>",
    description = ["One or more APK files or glob patterns (e.g. *.apk)."],
  )
  lateinit var inputs: List<String>

  @Option(names = ["--json"], description = ["Output structured JSON report."])
  var json: Boolean = false

  @Option(names = ["--idsig"], description = ["Explicit v4 .idsig signature file (single APK only)."])
  var idsigPath: String? = null

  override fun call(): Int {
    val files = CliHelpers.expandApkInputs(inputs)
    if (files.isEmpty()) {
      System.err.println(
        if (root.isFrench) "Erreur : aucun fichier APK trouvé." else "Error: no matching APK files found."
      )
      return ExitCodes.IO_ERROR
    }
    val explicitIdsig = idsigPath?.let { File(it) }
    val reports = mutableListOf<ApkVerificationReport>()
    for (file in files) {
      reports += ApkVerifierEngine.verify(file, if (files.size == 1) explicitIdsig else null)
    }

    if (json) {
      println(ReportFormatters.verificationToJson(reports))
    } else {
      reports.forEach { print(ReportFormatters.verificationToText(it, root.isFrench)) }
    }
    return if (reports.all { it.verified }) ExitCodes.OK else ExitCodes.VERIFICATION_FAILED
  }
}

@Command(
  name = "resign",
  mixinStandardHelpOptions = true,
  description = ["Resign one or multiple APKs using an .ask, .jks, or .p12 key with automatic post-sign verification."],
)
class ResignCommand : Callable<Int> {
  @ParentCommand lateinit var root: AppsignCommand

  @Parameters(
    arity = "1..*",
    paramLabel = "<apk>",
    description = ["One or more APK files or glob patterns."],
  )
  lateinit var inputs: List<String>

  @Option(names = ["--key"], description = ["Path to APPSIGN .ask key container."])
  var askFile: File? = null

  @Option(names = ["--keystore"], description = ["Path to .jks or .p12/.pfx keystore."])
  var keystoreFile: File? = null

  @Option(names = ["--alias"], description = ["Key alias inside JKS/PKCS#12 keystore."])
  var alias: String? = null

  @Option(names = ["--pass"], description = ["Passphrase for ASK-LOCKED or keystore store password."])
  var pass: String? = null

  @Option(names = ["--key-pass"], description = ["Private key password (if different from keystore password)."])
  var keyPass: String? = null

  @Option(names = ["-o", "--output"], description = ["Output file (single APK) or output directory (batch)."])
  var output: File? = null

  @Option(names = ["--v1"], description = ["Enable JAR v1 signing."])
  var v1: Boolean = false

  @Option(names = ["--v2"], description = ["Enable APK Signature Scheme v2."])
  var v2: Boolean = false

  @Option(names = ["--v3"], description = ["Enable APK Signature Scheme v3."])
  var v3: Boolean = false

  @Option(names = ["--v31"], description = ["Enable APK Signature Scheme v3.1."])
  var v31: Boolean = false

  @Option(names = ["--v4"], description = ["Enable APK Signature Scheme v4 (.idsig)."])
  var v4: Boolean = false

  @Option(names = ["--no-align"], description = ["Skip pure-JVM zipalign pre-pass before signing."])
  var noAlign: Boolean = false

  @Option(names = ["--min-sdk"], description = ["Override minSdkVersion passed to apksig."])
  var minSdk: Int? = null

  @Option(names = ["--json"], description = ["Output structured JSON report."])
  var json: Boolean = false

  override fun call(): Int {
    if ((askFile == null && keystoreFile == null) || (askFile != null && keystoreFile != null)) {
      System.err.println(
        if (root.isFrench) {
          "Erreur : spécifiez exactement une source de clé (--key <fichier.ask> OU --keystore <fichier.jks|.p12>)."
        } else {
          "Error: specify exactly one key source (--key <file.ask> OR --keystore <file.jks|.p12>)."
        }
      )
      return ExitCodes.USAGE_ERROR
    }

    val files = CliHelpers.expandApkInputs(inputs)
    if (files.isEmpty()) {
      System.err.println(
        if (root.isFrench) "Erreur : aucun fichier APK trouvé." else "Error: no matching APK files found."
      )
      return ExitCodes.IO_ERROR
    }

    val material = resolveKeyMaterial()

    val anyExplicitScheme = v1 || v2 || v3 || v31 || v4
    val options =
      if (anyExplicitScheme) {
        SigningOptions(
          enableV1 = v1,
          enableV2 = v2,
          enableV3 = v3,
          enableV31 = v31,
          enableV4 = v4,
          alignBeforeSign = !noAlign,
          minSdkVersion = minSdk,
        )
      } else {
        SigningOptions(
          enableV1 = true,
          enableV2 = true,
          enableV3 = true,
          enableV31 = false,
          enableV4 = false,
          alignBeforeSign = !noAlign,
          minSdkVersion = minSdk,
        )
      }

    val results = mutableListOf<ApkResignResult>()
    if (files.size == 1 && output != null && output!!.name.endsWith(".apk", ignoreCase = true)) {
      results += ApkSignerEngine.resign(files.first(), output!!, material, options)
    } else {
      val outDir = output ?: File("signed")
      results += ApkSignerEngine.resignBatch(files, outDir, material, options)
    }

    if (json) {
      println(ReportFormatters.resignToJson(results))
    } else {
      results.forEach { print(ReportFormatters.resignToText(it, root.isFrench)) }
    }

    return if (results.all { it.success }) ExitCodes.OK else ExitCodes.VERIFICATION_FAILED
  }

  private fun resolveKeyMaterial(): UnlockedKeyMaterial {
    askFile?.let { file ->
      val container = AskKeyManager.readAsk(file)
      val pw =
        if (container.mode == AskMode.ASK_LOCKED) {
          CliHelpers.requireOrPromptPassword(pass, "ASK passphrase: ")
        } else {
          null
        }
      return AskKeyManager.unlockAsk(container, pw)
    }
    val ks = keystoreFile!!
    val storePw = CliHelpers.requireOrPromptPassword(pass, "Keystore password: ")
    val keyPw = keyPass?.toCharArray() ?: storePw
    val container =
      if (ks.name.endsWith(".p12", ignoreCase = true) || ks.name.endsWith(".pfx", ignoreCase = true)) {
        AskKeyManager.importFromPkcs12(ks, storePw, alias, keyPw)
      } else {
        AskKeyManager.importFromJks(ks, storePw, alias, keyPw)
      }
    return AskKeyManager.unlockAsk(container, null)
  }
}

@Command(
  name = "key",
  mixinStandardHelpOptions = true,
  description = ["Manage APPSIGN Key containers (.ask) and convert JKS / PKCS#12 / PKCS#8 / X.509."],
  subcommands = [
    KeyCreateCommand::class,
    KeyInspectCommand::class,
    KeyImportCommand::class,
    KeyExportCommand::class,
  ],
)
class KeyCommand : Callable<Int> {
  override fun call(): Int {
    CommandLine(this).usage(System.out)
    return ExitCodes.OK
  }
}

@Command(name = "create", mixinStandardHelpOptions = true, description = ["Create a new .ask key container."])
class KeyCreateCommand : Callable<Int> {
  @ParentCommand lateinit var parent: KeyCommand

  @Option(names = ["--alias"], description = ["Key alias (default: appsign-key)."])
  var alias: String = "appsign-key"

  @Option(names = ["--alg"], description = ["Algorithm: rsa2048, rsa3072, rsa4096, ec256, ec384."])
  var alg: String = "rsa2048"

  @Option(names = ["--cn"], description = ["Certificate Common Name (CN)."])
  var cn: String = "APPSIGN Key"

  @Option(names = ["--org"], description = ["Certificate Organization (O)."])
  var org: String = "APPSIGN"

  @Option(names = ["--ou"], description = ["Certificate Organizational Unit (OU)."])
  var ou: String = "Security"

  @Option(names = ["--country"], description = ["Certificate Country code (C)."])
  var country: String = "FR"

  @Option(names = ["--years"], description = ["Certificate validity in years (default: 25)."])
  var years: Int = 25

  @Option(names = ["--pass"], description = ["Passphrase for ASK-LOCKED mode. Omit or use --open for ASK-OPEN."])
  var pass: String? = null

  @Option(names = ["--open"], description = ["Explicitly create an unencrypted ASK-OPEN key without password."])
  var openMode: Boolean = false

  @Option(names = ["--notes"], description = ["Optional metadata notes."])
  var notes: String = ""

  @Option(names = ["-o", "--out"], description = ["Output .ask file path (default: <alias>.ask)."])
  var outFile: File? = null

  @Option(names = ["--json"], description = ["Output inspection summary as JSON."])
  var json: Boolean = false

  override fun call(): Int {
    val algorithm =
      when (alg.lowercase()) {
        "rsa2048", "rsa" -> KeyAlgorithm.RSA_2048
        "rsa3072" -> KeyAlgorithm.RSA_3072
        "rsa4096" -> KeyAlgorithm.RSA_4096
        "ec256", "ec", "p256" -> KeyAlgorithm.EC_P256
        "ec384", "p384" -> KeyAlgorithm.EC_P384
        else -> {
          System.err.println("Unsupported algorithm: $alg")
          return ExitCodes.USAGE_ERROR
        }
      }
    val effectivePass = if (openMode) null else pass?.toCharArray()
    val container =
      AskKeyManager.createAsk(
        CreateAskOptions(
          alias = alias,
          algorithm = algorithm,
          commonName = cn,
          organization = org,
          organizationalUnit = ou,
          country = country,
          validityYears = years,
          passphrase = effectivePass,
          notes = notes,
        )
      )
    val target = outFile ?: File("${alias.replace(Regex("[^a-zA-Z0-9_-]"), "_")}.ask")
    AskKeyManager.writeAsk(container, target)
    val inspected = AskKeyManager.inspectAsk(container)
    if (json) {
      println(ReportFormatters.askInspectToJson(inspected))
    } else {
      println("Created ${target.absolutePath}")
      print(ReportFormatters.askInspectToText(inspected, false))
    }
    return ExitCodes.OK
  }
}

@Command(name = "inspect", mixinStandardHelpOptions = true, description = ["Inspect metadata and certificate of an .ask file."])
class KeyInspectCommand : Callable<Int> {
  @Parameters(index = "0", paramLabel = "<file.ask>", description = ["Path to .ask file."])
  lateinit var askFile: File

  @Option(names = ["--json"], description = ["Output JSON report."])
  var json: Boolean = false

  override fun call(): Int {
    val inspected = AskKeyManager.inspectAsk(askFile)
    if (json) {
      println(ReportFormatters.askInspectToJson(inspected))
    } else {
      print(ReportFormatters.askInspectToText(inspected, false))
    }
    return ExitCodes.OK
  }
}

@Command(name = "import", mixinStandardHelpOptions = true, description = ["Import JKS, PKCS#12, or PKCS#8+X.509 into an .ask container."])
class KeyImportCommand : Callable<Int> {
  @Option(names = ["--from"], required = true, description = ["Source format: jks, p12, or pkcs8."])
  lateinit var format: String

  @Option(names = ["--in"], required = true, description = ["Input keystore or PKCS#8 private key file."])
  lateinit var inFile: File

  @Option(names = ["--cert"], description = ["X.509 certificate file (required when --from pkcs8)."])
  var certFile: File? = null

  @Option(names = ["--alias"], description = ["Alias to select or assign."])
  var alias: String? = null

  @Option(names = ["--store-pass"], description = ["Password for source JKS/PKCS#12."])
  var storePass: String? = null

  @Option(names = ["--key-pass"], description = ["Private key password inside source JKS/PKCS#12."])
  var keyPass: String? = null

  @Option(names = ["--ask-pass"], description = ["Optional passphrase to lock the resulting ASK container."])
  var askPass: String? = null

  @Option(names = ["-o", "--out"], required = true, description = ["Output .ask file."])
  lateinit var outFile: File

  override fun call(): Int {
    val container =
      when (format.lowercase()) {
        "p12", "pkcs12", "pfx" -> {
          val pw = CliHelpers.requireOrPromptPassword(storePass, "PKCS#12 password: ")
          AskKeyManager.importFromPkcs12(inFile, pw, alias, keyPass?.toCharArray() ?: pw, askPass?.toCharArray())
        }
        "jks" -> {
          val pw = CliHelpers.requireOrPromptPassword(storePass, "JKS password: ")
          AskKeyManager.importFromJks(inFile, pw, alias, keyPass?.toCharArray() ?: pw, askPass?.toCharArray())
        }
        "pkcs8", "pk8", "pem" -> {
          val cert = certFile ?: throw AskFormatException("--cert <x509.pem> is required when --from pkcs8")
          AskKeyManager.importFromPkcs8AndCert(
            pkcs8File = inFile,
            certFile = cert,
            alias = alias ?: inFile.nameWithoutExtension,
            askPassphrase = askPass?.toCharArray(),
          )
        }
        else -> {
          System.err.println("Unsupported --from format: $format")
          return ExitCodes.USAGE_ERROR
        }
      }
    AskKeyManager.writeAsk(container, outFile)
    println("Imported to ${outFile.absolutePath} (${container.mode})")
    return ExitCodes.OK
  }
}

@Command(name = "export", mixinStandardHelpOptions = true, description = ["Export an .ask key to ASK-OPEN, ASK-LOCKED, PKCS#12, JKS, or PKCS#8+X.509."])
class KeyExportCommand : Callable<Int> {
  @Parameters(index = "0", paramLabel = "<file.ask>", description = ["Source .ask container."])
  lateinit var askFile: File

  @Option(
    names = ["--format"],
    description = ["Export format: p12, jks, pkcs8, ask-open, ask-locked (default: p12)."],
  )
  var format: String = "p12"

  @Option(names = ["--pass"], description = ["Passphrase to unlock source ASK-LOCKED file."])
  var pass: String? = null

  @Option(names = ["--out-pass"], description = ["Password for exported keystore or ASK-LOCKED file."])
  var outPass: String? = null

  @Option(names = ["--alias"], description = ["Alias for exported JKS/PKCS#12 entry."])
  var alias: String? = null

  @Option(names = ["-o", "--out"], description = ["Output file path."])
  var outFile: File? = null

  @Option(names = ["--cert-out"], description = ["Output X.509 certificate path when --format pkcs8."])
  var certOutFile: File? = null

  override fun call(): Int {
    val container = AskKeyManager.readAsk(askFile)
    val unlockPass =
      if (container.mode == AskMode.ASK_LOCKED) {
        CliHelpers.requireOrPromptPassword(pass, "Source ASK passphrase: ")
      } else {
        null
      }
    val unlocked = AskKeyManager.unlockAsk(container, unlockPass)
    val base = askFile.nameWithoutExtension

    when (format.lowercase()) {
      "p12", "pkcs12" -> {
        val target = outFile ?: File("$base.p12")
        val pw = CliHelpers.requireOrPromptPassword(outPass, "Export PKCS#12 password: ")
        AskKeyManager.exportToPkcs12(unlocked, target, pw, alias ?: unlocked.alias)
        println("Exported PKCS#12 to ${target.absolutePath}")
      }
      "jks" -> {
        val target = outFile ?: File("$base.jks")
        val pw = CliHelpers.requireOrPromptPassword(outPass, "Export JKS password: ")
        AskKeyManager.exportToJks(unlocked, target, pw, pw, alias ?: unlocked.alias)
        println("Exported JKS to ${target.absolutePath}")
      }
      "pkcs8", "pk8", "pem" -> {
        val keyTarget = outFile ?: File("$base.pk8.pem")
        val certTarget = certOutFile ?: File("$base.cert.pem")
        val warning = AskKeyManager.exportToPkcs8AndCert(unlocked, keyTarget, certTarget, pemEncoded = true)
        println("Exported PKCS#8 key to ${keyTarget.absolutePath} and X.509 cert to ${certTarget.absolutePath}")
        System.err.println(warning)
      }
      "ask-open" -> {
        val target = outFile ?: File("$base.open.ask")
        val openContainer = AskKeyManager.changeProtection(container, unlockPass, null)
        AskKeyManager.writeAsk(openContainer, target)
        println("Exported ASK-OPEN to ${target.absolutePath}")
        System.err.println(AskKeyManager.UNENCRYPTED_WARNING_EN)
      }
      "ask-locked" -> {
        val target = outFile ?: File("$base.locked.ask")
        val pw = CliHelpers.requireOrPromptPassword(outPass, "New ASK-LOCKED passphrase: ")
        val lockedContainer = AskKeyManager.changeProtection(container, unlockPass, pw)
        AskKeyManager.writeAsk(lockedContainer, target)
        println("Exported ASK-LOCKED to ${target.absolutePath}")
      }
      else -> {
        System.err.println("Unsupported export format: $format")
        return ExitCodes.USAGE_ERROR
      }
    }
    return ExitCodes.OK
  }
}

object CliHelpers {
  fun expandApkInputs(patterns: List<String>): List<File> {
    val resolved = linkedSetOf<File>()
    for (raw in patterns) {
      val direct = File(raw)
      if (direct.exists() && direct.isFile) {
        resolved += direct
      } else if (direct.exists() && direct.isDirectory) {
        direct.listFiles()?.filter { it.isFile && it.extension.equals("apk", ignoreCase = true) }?.sortedBy { it.name }
          ?.let { resolved.addAll(it) }
      } else if (raw.contains("*") || raw.contains("?")) {
        val parent = direct.parentFile ?: File(".")
        val patternName = direct.name
        if (parent.exists() && parent.isDirectory) {
          val matcher = FileSystems.getDefault().getPathMatcher("glob:$patternName")
          parent.toPath().let { parentPath ->
            Files.list(parentPath).use { stream ->
              stream
                .filter { Files.isRegularFile(it) && matcher.matches(it.fileName) }
                .sorted()
                .forEach { resolved += it.toFile() }
            }
          }
        }
      } else {
        throw ApkOperationException("Input APK does not exist: $raw")
      }
    }
    return resolved.toList()
  }

  fun requireOrPromptPassword(explicit: String?, prompt: String): CharArray {
    if (!explicit.isNullOrEmpty()) return explicit.toCharArray()
    val console = System.console()
    if (console != null) {
      val entered = console.readPassword(prompt)
      if (entered != null && entered.isNotEmpty()) return entered
    }
    throw AskPasswordRequiredException("Missing required password ($prompt). Pass it via CLI option.")
  }
}

fun executeCli(
  args: Array<String>,
  out: PrintStream = System.out,
  err: PrintStream = System.err,
): Int {
  val prevOut = System.out
  val prevErr = System.err
  System.setOut(out)
  System.setErr(err)
  return try {
    val cmd = CommandLine(AppsignCommand())
    cmd.setExecutionExceptionHandler { ex, _, _ ->
      err.println("Error: ${ex.message}")
      when (ex) {
        is AskPasswordRequiredException,
        is AskDecryptionException,
        is AskFormatException,
        is AskKeyMismatchException -> ExitCodes.CRYPTO_ERROR
        is ApkOperationException,
        is java.io.IOException -> ExitCodes.IO_ERROR
        else -> ExitCodes.CRYPTO_ERROR
      }
    }
    cmd.execute(*args)
  } finally {
    System.setOut(prevOut)
    System.setErr(prevErr)
  }
}

fun main(args: Array<String>) {
  val code = executeCli(args)
  exitProcess(code)
}
