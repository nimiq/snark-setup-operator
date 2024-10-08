# Make sure you configure GCR for your local docker engine
# https://cloud.google.com/container-registry/docs/pushing-and-pulling

import click
from subprocess import Popen, PIPE, run
import sys 

@click.group()
@click.option('--debug/--no-debug', default=False)
def cli(debug):
    click.echo('Debug mode is %s' % ('on' if debug else 'off'))

@cli.command()  
@click.option('--repo', default="us-west1-docker.pkg.dev/iron-fountain-169200/nimiq")
@click.option('--tag', default="test")
def release_docker(repo, tag):
    # Build and push Service
    build_command = f'docker build --platform linux/amd64 -f Dockerfile -t {repo}/snark-ceremony-operator:{tag} .'
    print(f"Running Command: {build_command}")
    run([build_command], shell=True, stdin=PIPE)
    
    push_command = f'docker push {repo}/snark-ceremony-operator:{tag}'
    print(f"Running Command: {push_command}")
    push = Popen([push_command], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = push.communicate()
    if error:
        print(error.decode("utf-8") )
    if output:
        print(output.decode("utf-8") )
        
if __name__ == "__main__":
    cli()