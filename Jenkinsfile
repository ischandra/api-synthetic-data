// Generates synthetic API request data from a spec and archives it.
// Needs python3 (3.9+) on the agent.
pipeline {
    agent any

    parameters {
        string(name: 'SPEC', defaultValue: 'examples/shop-api.openapi.yaml', description: 'OpenAPI file or URL')
        string(name: 'POSTMAN', defaultValue: '', description: 'Optional Postman collection file or URL')
        string(name: 'COUNT', defaultValue: '5', description: 'Valid requests per endpoint')
        string(name: 'FORMATS', defaultValue: 'json,csv,apitest,postman', description: 'json,jsonl,csv,apitest,postman')
        string(name: 'SEED', defaultValue: '', description: 'Seed to reproduce a previous run (default: build number)')
        booleanParam(name: 'HOSTILE', defaultValue: false, description: 'Add SQL-injection/XSS/unicode cases')
    }

    options { timestamps() }

    stages {
        stage('Setup') {
            steps {
                sh '''
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install -q -r requirements.txt
                '''
            }
        }
        stage('Self-tests') {
            steps {
                sh '. .venv/bin/activate && pytest -q --junitxml=reports/selftests.xml'
            }
        }
        stage('Generate') {
            steps {
                // parameters are read as shell variables (not Groovy-interpolated)
                sh '''
                    . .venv/bin/activate
                    ARGS="--openapi $SPEC"
                    [ -n "$POSTMAN" ] && ARGS="$ARGS --postman $POSTMAN"
                    [ "$HOSTILE" = "true" ] && ARGS="$ARGS --hostile"
                    python -m apisynth generate $ARGS -n "$COUNT" -f "$FORMATS" \
                        --seed "${SEED:-$BUILD_NUMBER}" -o synthetic-data --strict
                '''
            }
        }
    }

    post {
        always {
            junit allowEmptyResults: true, testResults: 'reports/*.xml'
            archiveArtifacts artifacts: 'synthetic-data/**', allowEmptyArchive: true
        }
    }
}
