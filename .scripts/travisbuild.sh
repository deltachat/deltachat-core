# perform travis jobs on PRs and after merges to master.
# triggered from .travis.yml 

set -e -x
MYDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

export DOCKERIMAGE=deltachat/test1

# docker pull $DOCKERIMAGE

# cd to repository checkout dir 
cd $MYDIR/..

# run everything else inside docker (TESTS, DOCS, WHEELS) 
docker run -e TESTS -e WHEELS -e DOCS --rm -it -v $(pwd):/mnt $DOCKERIMAGE /mnt/.scripts/run_all.sh
