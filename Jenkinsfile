// Generates synthetic API request data from a spec and archives it.
// Needs python3 (3.9+) on the agent.
pipeline {
    agent any

    parameters {
        string(name: 'API_URL', defaultValue: '', description: 'Test this API end to end (base URL, spec or Swagger UI URL). Empty: only generate data from SPEC')
        choice(name: 'MODE', choices: ['safe', 'read', 'all'], description: 'safe: change only records the run created; read: GET only; all: anything')
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
        stage('Test API') {
            when { expression { params.API_URL?.trim() } }
            steps {
                // Credentials: bind them with withCredentials / credentials() as these environment variables.
                // They are passed as env:NAME so the values never appear in the command line or the log.
                sh '''
                    . .venv/bin/activate
                    ARGS=""
                    [ -n "$API_TOKEN" ] && ARGS="$ARGS --token env:API_TOKEN"
                    [ -n "$API_KEY" ] && ARGS="$ARGS --api-key env:API_KEY"
                    [ -n "$API_BASIC" ] && ARGS="$ARGS --basic env:API_BASIC"
                    [ -n "$API_CLIENT_ID" ] && ARGS="$ARGS --client-id env:API_CLIENT_ID --client-secret env:API_CLIENT_SECRET"
                    [ -n "$API_TOKEN_URL" ] && ARGS="$ARGS --token-url $API_TOKEN_URL"
                    [ -n "$API_EXTRA_ARGS" ] && ARGS="$ARGS $API_EXTRA_ARGS"
                    # exit 1 = bugs found: reported through junit (build UNSTABLE); exit 2 = error: fail the build
                    rc=0
                    python -m apisynth test "$API_URL" --mode "$MODE" --seed "${SEED:-$BUILD_NUMBER}" -o reports/api-test $ARGS || rc=$?
                    [ "$rc" -le 1 ]
                '''
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
            junit allowEmptyResults: true, testResults: 'reports/**/*.xml'
            archiveArtifacts artifacts: 'synthetic-data/**, reports/**', allowEmptyArchive: true
        }
    }
}
