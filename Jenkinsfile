node {
    stage('Preparation') {
        checkout scm
        versionNumber = VersionNumber versionNumberString: '${BUILD_DATE_FORMATTED, "yy.MM"}.${BUILDS_THIS_MONTH}', versionPrefix: '', buildsAllTime: '12'
        echo "VersionNumber: ${versionNumber}"
    }
    stage('Build Gradle project') {
        sh "/usr/lib/gradle/4.3.1/bin/gradle clean build"
    }
    stage('Push Docker image') {
        parallel (
            "turnstile-audirectdebit-gw" : {
                sh "docker tag inomial.io/turnstile-audirectdebit-gw inomial.io/turnstile-audirectdebit-gw:${versionNumber}"

                // archive image
                sh "docker save inomial.io/turnstile-audirectdebit-gw:${versionNumber} | gzip > turnstile-audirectdebit-gw-${versionNumber}.tar.gz"

                // tag and push if tests pass (as $revision and as latest)
                sh "docker push inomial.io/turnstile-audirectdebit-gw:${versionNumber}"
                sh "docker push inomial.io/turnstile-audirectdebit-gw:latest"
            }
        )

        // send email/slack
        // cleanup images
    }
    stage('Results') {
        currentBuild.displayName = versionNumber
        archive '*.tar.gz'
        archive 'build/libs/*.jar'
        // cleanup workspace
        step([$class: 'WsCleanup'])
    }
}
