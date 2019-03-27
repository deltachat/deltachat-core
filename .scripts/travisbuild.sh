# called from .travis.yml 

if [ -n "$WHEEL" ]; then 
    bash $TRAVIS_BUILD_DIR/.scripts/buildwheel.sh 
fi

