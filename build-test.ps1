param(
    [switch]$SkipBuild
)

$dockerArgs = @()
if($SkipBuild) {
    $dockerArgs += "--build"
} else {
    dotnet publish src/certz/certz.csproj -c Debug -o debug
}

docker network rm certz_default --force
docker compose -f docker-compose.test.yml up $dockerArgs certz-test