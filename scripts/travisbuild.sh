# perform travis jobs on PRs and after merges to master.
# triggered from .travis.yml 

set -e -x

export DOCKERIMAGE=${DOCKERIMAGE:-deltachat/test7}
export BRANCH=${CIRCLE_BRANCH:-test7}
    
# run doxygen on c-source (needed by later doc-generation steps).
# XXX modifies the host filesystem docs/xml and docs/html directories
# which you can then only remove with "sudo rm -rf docs/html docs/xml"
docker run --rm -it -v $PWD:/mnt -w /mnt/docs deltachat/doxygen doxygen

# run everything else inside docker (TESTS, DOCS, WHEELS) 
docker run -e DELTA_UPLOAD_SSH_KEY -e BRANCH -e DEVPI_LOGIN -e TESTS -e WHEELS -e DOCS \
           --rm -it -v $(pwd):/mnt -w /mnt \
           $DOCKERIMAGE /mnt/scripts/run_all.sh

