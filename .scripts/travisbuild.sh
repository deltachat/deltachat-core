# perform travis jobs on PRs and after merges to master.
# triggered from .travis.yml 

set -e -x

export DOCKERIMAGE=deltachat/test5

# docker pull $DOCKERIMAGE

# cd to repository checkout dir 

# run everything else inside docker (TESTS, DOCS, WHEELS) 
docker run -e TESTS -e WHEELS -e DOCS \
           --rm -it -v $(pwd):/mnt \
           -w /mnt \
           $DOCKERIMAGE /mnt/.scripts/run_all.sh
