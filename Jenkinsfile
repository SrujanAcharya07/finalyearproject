pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 20, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'DOCKER_IMAGE', defaultValue: 'phishops-playbook', description: 'Image name, for example docker.io/your-user/phishops-playbook')
        booleanParam(name: 'PUSH_IMAGE', defaultValue: false, description: 'Push the image after a successful smoke test')
        string(name: 'REGISTRY_CREDENTIALS_ID', defaultValue: 'docker-registry', description: 'Jenkins username/password credential ID used only when PUSH_IMAGE is enabled')
    }

    environment {
        IMAGE_TAG = "${params.DOCKER_IMAGE}:${env.BUILD_NUMBER}"
        IMAGE_LATEST = "${params.DOCKER_IMAGE}:latest"
        CONTAINER_NAME = "phishops-ci-${env.BUILD_TAG.replaceAll('[^A-Za-z0-9_.-]', '-')}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Unit tests') {
            steps {
                sh '''#!/bin/sh
                    set -eu
                    python3 -m venv .venv
                    .venv/bin/python -m pip install --upgrade pip
                    .venv/bin/pip install -r requirements.txt
                    .venv/bin/pytest -q --junitxml=test-results.xml
                '''
            }
            post {
                always {
                    junit testResults: 'test-results.xml', allowEmptyResults: true
                }
            }
        }

        stage('Build image') {
            steps {
                sh 'docker build --pull -t "$IMAGE_TAG" -t "$IMAGE_LATEST" .'
            }
        }

        stage('Container smoke test') {
            steps {
                sh '''#!/bin/sh
                    set -eu
                    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
                    docker run -d --name "$CONTAINER_NAME" -p 18080:3000 \\
                        -e SECRET_KEY=jenkins-smoke-test \\
                        -e DATABASE_PATH=/tmp/phishops-smoke.db \\
                        "$IMAGE_TAG" >/dev/null
                    trap 'docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT
                    i=0
                    until curl --fail --silent http://127.0.0.1:18080/health >/dev/null; do
                        i=$((i + 1))
                        [ "$i" -lt 30 ] || { docker logs "$CONTAINER_NAME"; exit 1; }
                        sleep 2
                    done
                    curl --fail --silent http://127.0.0.1:18080/health
                '''
            }
        }

        stage('Push image') {
            when {
                expression { return params.PUSH_IMAGE }
            }
            steps {
                withCredentials([usernamePassword(credentialsId: params.REGISTRY_CREDENTIALS_ID, usernameVariable: 'REGISTRY_USER', passwordVariable: 'REGISTRY_PASSWORD')]) {
                    sh '''#!/bin/sh
                        set -eu
                        REGISTRY_HOST=$(printf '%s' "$DOCKER_IMAGE" | cut -d/ -f1)
                        case "$REGISTRY_HOST" in
                            *.*|localhost:*) printf '%s' "$REGISTRY_PASSWORD" | docker login "$REGISTRY_HOST" --username "$REGISTRY_USER" --password-stdin ;;
                            *) printf '%s' "$REGISTRY_PASSWORD" | docker login --username "$REGISTRY_USER" --password-stdin ;;
                        esac
                        docker push "$IMAGE_TAG"
                        docker push "$IMAGE_LATEST"
                        docker logout "$REGISTRY_HOST" >/dev/null 2>&1 || true
                    '''
                }
            }
        }
    }

    post {
        always {
            sh 'docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true'
            sh 'docker image prune -f >/dev/null 2>&1 || true'
        }
    }
}
