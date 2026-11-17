import org.gradle.api.file.DuplicatesStrategy
import org.gradle.jvm.tasks.Jar

plugins {
  alias(libs.plugins.kotlin.jvm)
  application
}

java {
  sourceCompatibility = JavaVersion.VERSION_11
  targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
  jvmToolchain(11)
}

application {
  mainClass.set("com.hephaistos.appsign.cli.AppsignCliKt")
  applicationName = "appsign"
}

dependencies {
  implementation(project(":appsign-core"))
  implementation(libs.picocli)
  testImplementation(libs.junit)
}

tasks.register<Jar>("fatJar") {
  group = "build"
  description = "Assembles a standalone executable fat JAR for Termux and Linux."
  archiveBaseName.set("appsign-cli")
  archiveClassifier.set("all")
  duplicatesStrategy = DuplicatesStrategy.EXCLUDE
  manifest {
    attributes["Main-Class"] = "com.hephaistos.appsign.cli.AppsignCliKt"
  }
  from(sourceSets.main.get().output)
  dependsOn(configurations.runtimeClasspath)
  from({
    configurations.runtimeClasspath.get()
      .filter { it.name.endsWith(".jar") }
      .map { zipTree(it) }
  }) {
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/versions/*/module-info.class", "module-info.class")
  }
}
