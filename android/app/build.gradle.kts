plugins { id("com.android.application") }

val copyWorkbenchHtml by tasks.registering(Copy::class) {
    from(rootProject.file("../index.html"))
    into(layout.buildDirectory.dir("generated/zpx0xyAssets"))
    rename { "index.html" }
}

android {
    namespace = "io.zpx0xy"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.zpx0xy"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].assets.srcDir(layout.buildDirectory.dir("generated/zpx0xyAssets"))
    packaging {
        resources {
            pickFirsts += "META-INF/LICENSE.md"
        }
    }
}

tasks.named("preBuild").configure { dependsOn(copyWorkbenchHtml) }

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
}
